package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"kitsune/internal/db"
	"kitsune/internal/proto"
	"kitsune/internal/selfsteal"
)

var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// selfstealInbounds – подключения, у которых маскировка идёт через REALITY (их сайт-заглушка и подменяет).
func selfstealInbounds() []db.Inbound {
	var out []db.Inbound
	list, _ := db.GetInbounds()
	for _, ib := range list {
		if ib.Kind == string(proto.VlessReality) || ib.Kind == string(proto.VlessXHTTP) {
			out = append(out, ib)
		}
	}
	return out
}

func portFree(p int) bool {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

// selfstealCheck проверяет то, без чего сайт-заглушка не заработает, и говорит о каждой проблеме отдельно (код возврата 1).
func selfstealCheck(domain string) bool {
	ok := true
	if !domainRe.MatchString(domain) {
		fmt.Println("✗  \"" + domain + "\" doesn't look like a domain (use a Latin-letter name without https://, e.g. vpn.example.com)")
		return false
	}
	ips, err := net.LookupHost(domain)
	my := publicIP()
	switch {
	case err != nil || len(ips) == 0:
		fmt.Printf("✗  Domain %s has no A record. Create one pointing to this server's IP (%s) and wait a few minutes.\n", domain, my)
		ok = false
	case !contains(ips, my):
		fmt.Printf("✗  Domain %s points to %s, but this server is %s. Fix the A record (if the domain is behind a proxy like Cloudflare, turn proxying off).\n", domain, strings.Join(ips, ", "), my)
		ok = false
	}
	if !portFree(80) && !heldByKitsune(80) {
		fmt.Println("✗  Port 80/tcp is used by another program, so Let's Encrypt can't verify the domain. Free the port and try again.")
		ok = false
	}
	return ok
}

// cmdSelfSteal: kit selfsteal ДОМЕН | off | status
func cmdSelfSteal(a []string) {
	quietInit()
	cur := selfsteal.Domain()
	if len(a) == 0 || a[0] == "status" {
		if cur == "" {
			fmt.Println("Decoy site on your own domain: off. To enable: kit selfsteal vpn.example.com")
		} else {
			fmt.Println("Decoy site on your own domain:", cur)
		}
		return
	}
	if a[0] == "off" {
		_ = selfsteal.Set("")
		for _, ib := range selfstealInbounds() {
			s := proto.ParseSettings(ib.Settings)
			if s.Target == selfsteal.Addr {
				s.Target = ""
				// свой домен без заглушки замкнулся бы на себя: ставим обычный сайт из списка
				pick, _ := rand.Int(rand.Reader, big.NewInt(int64(len(proto.DefaultSNIs))))
				s.SNI = proto.DefaultSNIs[pick.Int64()]
				_, _ = db.DB.Exec("UPDATE inbounds SET settings = ? WHERE id = ?", s.JSON(), ib.ID)
			}
		}
		fmt.Println("✓  Decoy site turned off. Pick a REALITY masking site in Settings → Masking.")
		restartHint()
		return
	}
	domain := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(a[0], ".")))
	if !selfstealCheck(domain) {
		os.Exit(1)
	}
	// Порт 80 для проверки домена держит сама работающая служба (так бывает после HTTPS панели на домене): команда запускается
	// отдельным процессом и этот порт занять не может, поэтому на время выпуска службу останавливаем и потом возвращаем.
	svcWasUp := heldByKitsune(80)
	if svcWasUp {
		fmt.Println("…  Port 80 is held by the running Kitsune service: stopping it for the certificate request")
		cmdService("stop")
	}
	startBack := func() {
		if svcWasUp {
			cmdService("start")
		}
	}
	fmt.Printf("…  Getting a Let's Encrypt certificate for %s (up to a minute)\n", domain)
	_ = selfsteal.Set(domain)
	if _, _, err := selfsteal.Ensure(domain); err != nil {
		_ = selfsteal.Set(cur)
		fmt.Println("✗  Let's Encrypt did not issue a certificate:", err)
		fmt.Println("   Common causes: the A record hasn't updated yet, port 80 is blocked by the host or firewall, or the domain is behind a proxy.")
		startBack()
		os.Exit(1)
	}
	n := 0
	for _, ib := range selfstealInbounds() {
		s := proto.ParseSettings(ib.Settings)
		s.SNI, s.Target = domain, selfsteal.Addr
		_, _ = db.DB.Exec("UPDATE inbounds SET sni = ?, settings = ? WHERE id = ?", domain, s.JSON(), ib.ID)
		n++
	}
	fmt.Printf("✓  Decoy site on %s is ready (certificate issued, REALITY connections switched: %d)\n", domain, n)
	if svcWasUp {
		startBack()
	} else {
		restartHint()
	}
}

func restartHint() {
	if os.Getenv("KITSUNE_NO_RESTART") == "" {
		if serviceState() == "running" {
			cmdService("restart")
		}
	}
}

// heldByKitsune: порт держит сама служба Kitsune (так бывает с портом 80 для продления сертификатов) – это не помеха.
func heldByKitsune(port int) bool {
	out, err := exec.Command("ss", "-H", "-ltnp", fmt.Sprintf("sport = :%d", port)).Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return false
	}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if !strings.Contains(l, `"kitsune"`) {
			return false
		}
	}
	return true
}
