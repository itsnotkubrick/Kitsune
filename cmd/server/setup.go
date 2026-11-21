package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"kitsune/internal/db"
	"kitsune/internal/masking"
	"kitsune/internal/proto"
)

// quickKinds – имена протоколов для установщика и команды kit setup.
var quickKinds = []struct {
	Name string
	Kind proto.Kind
}{
	{"reality", proto.VlessReality}, {"xhttp", proto.VlessXHTTP}, {"ws", proto.VlessWS}, {"trojan", proto.TrojanGRPC},
	{"vmess", proto.VmessWS}, {"ss", proto.SS2022}, {"hy2", proto.Hysteria2}, {"tuic", proto.TUIC},
	{"mtproto", proto.MTProto}, {"awg", proto.AWG}, {"awg3", proto.AWG3},
	// NaiveProxy работает только с доверенным сертификатом на домен (без него в подписку sing-box не попадает), Mieru – только Linux.
	{"naive", proto.Naive}, {"mieru", proto.Mieru},
}

// Запасные сайты для маскировки REALITY: нужны TLS 1.3 и HTTP/2.
var fallbackSNI = []string{"dl.google.com", "www.amazon.com", "www.samsung.com", "www.yahoo.com"}

func sniWorks(domain string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ips, err := net.LookupHost(domain)
	if err != nil || len(ips) == 0 {
		return false
	}
	_, ok := masking.Check(ctx, ips[0], domain)
	return ok
}

// findSNI подбирает сайт для REALITY: сначала соседи по подсети сервера, затем запасной список.
func findSNI(ip string) (string, string) {
	if net.ParseIP(ip).To4() != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		if c := masking.Scan(ctx, ip, 6); len(c) > 0 {
			return c[0].Domain, "subnet neighbour"
		}
	}
	for _, d := range fallbackSNI {
		if sniWorks(d) {
			return d, "from the fallback list"
		}
	}
	return "", ""
}

// pickSecondSNI выбирает для XHTTP имя, отличное от имени REALITY: два подключения под одним именем легче заметить.
// Берётся первый подходящий кандидат, не совпадающий с первым именем; пусто – второго имени не нашлось.
func pickSecondSNI(first string, candidates []string, works func(string) bool) string {
	for _, d := range candidates {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" && d != strings.ToLower(strings.TrimSpace(first)) && works(d) {
			return d
		}
	}
	return ""
}

// findSecondSNI ищет второе имя среди соседей по подсети, затем в запасном списке.
func findSecondSNI(ip, first string) string {
	var names []string
	if net.ParseIP(ip).To4() != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		for _, c := range masking.Scan(ctx, ip, 6) {
			names = append(names, c.Domain) // соседей Scan уже проверил: повторно не проверяем
		}
	}
	checked := map[string]bool{}
	for _, n := range names {
		checked[n] = true
	}
	names = append(names, fallbackSNI...)
	return pickSecondSNI(first, names, func(d string) bool { return checked[d] || sniWorks(d) })
}

// cmdSNI: kit sni check <домен> | kit sni find [ip] – помощники установщика (код возврата 0 – подходит).
func cmdSNI(a []string) {
	if len(a) >= 2 && a[0] == "check" {
		if sniWorks(strings.ToLower(strings.TrimSpace(a[1]))) {
			fmt.Println("✓  Works for REALITY: TLS 1.3 and HTTP/2")
			return
		}
		fmt.Println("✗  Doesn't answer over TLS 1.3 and HTTP/2 – REALITY won't work with it")
		os.Exit(1)
	}
	ip := publicIP()
	if len(a) >= 2 && a[1] != "" {
		ip = a[1]
	}
	d, how := findSNI(ip)
	if d == "" {
		fmt.Println("✗  No suitable site found")
		os.Exit(1)
	}
	fmt.Println(d)
	fmt.Fprintln(os.Stderr, "   ("+how+")")
}

// cmdSetup создаёт выбранные подключения и первого пользователя (вызывает установщик до запуска службы).
//
//	kit setup --protocols reality,ws --sni auto --user name --host 1.2.3.4
func cmdSetup(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	protos := fs.String("protocols", "", "comma-separated protocols: reality,xhttp,ws,trojan,vmess,ss,hy2,tuic,mtproto,awg,awg3,naive,mieru or all (all 13)")
	sni := fs.String("sni", "auto", "REALITY masking site: auto or a domain")
	target := fs.String("target", "", "where REALITY sends foreign traffic (for a decoy site on your own domain)")
	user := fs.String("user", "user", "name of the first user")
	host := fs.String("host", "", "server address used in links")
	_ = fs.Parse(args)
	db.InitDB()
	if *host != "" {
		_ = db.SetSetting("public_host", *host)
	}
	var kinds []proto.Kind
	want := map[string]bool{}
	for _, n := range strings.Split(strings.ToLower(*protos), ",") {
		if n = strings.TrimSpace(n); n != "" {
			want[n] = true
		}
	}
	if want["all"] {
		for _, q := range quickKinds {
			want[q.Name] = true
		}
	}
	for n := range want {
		ok := false
		for _, q := range quickKinds {
			if q.Name == n {
				ok = true
			}
		}
		if !ok && n != "all" {
			fmt.Printf("✗  Unknown protocol %q (available: reality, xhttp, ws, trojan, vmess, ss, hy2, tuic, mtproto, awg, awg3, naive, mieru, all)\n", n)
			os.Exit(1)
		}
	}
	for _, q := range quickKinds {
		if want[q.Name] {
			kinds = append(kinds, q.Kind)
		}
	}
	if len(kinds) == 0 {
		fmt.Println("…  No connections selected – the panel will stay empty, create them in the browser")
		return
	}
	mask := *sni
	needSNI := want["reality"] || want["xhttp"]
	if needSNI && (mask == "" || mask == "auto") {
		ip := *host
		if ip == "" {
			ip = publicIP()
		}
		fmt.Println("…  Looking for a REALITY masking site among subnet neighbours (up to 253 short TLS requests to neighbouring addresses of your host, 16 at a time)")
		d, how := findSNI(ip)
		if d == "" {
			fmt.Println("✗  Couldn't find a suitable REALITY masking site: set one with --sni (e.g. dl.google.com)")
			os.Exit(1)
		} else {
			mask = d
			fmt.Printf("✓  Masking site: %s (%s)\n", d, how)
		}
	}
	// XHTTP рядом с REALITY получает второе имя (с чужим сайтом под «своим» доменом это не нужно: там одна заглушка)
	second := ""
	if want["reality"] && want["xhttp"] && mask != "" && mask != "auto" && *target == "" {
		ip := *host
		if ip == "" {
			ip = publicIP()
		}
		if second = findSecondSNI(ip, mask); second != "" {
			fmt.Printf("✓  Second masking site for XHTTP: %s\n", second)
		} else {
			fmt.Printf("!  No second masking site found: REALITY and XHTTP will both use %s (change one in the panel, Masking)\n", mask)
		}
	}
	created := 0
	for _, k := range kinds {
		var patch map[string]any
		if needSNI && mask != "" && mask != "auto" && (k == proto.VlessReality || k == proto.VlessXHTTP) {
			patch = map[string]any{"sni": mask}
			if k == proto.VlessXHTTP && second != "" {
				patch["sni"] = second
			}
			if *target != "" {
				patch["target"] = *target
			}
		}
		ib, err := createInbound(k, "", 0, patch)
		if err != nil {
			fmt.Printf("!  %s: %v\n", k.Title(), err)
			continue
		}
		fmt.Printf("✓  %s – port %d\n", k.Title(), ib.Port)
		if info, ok := proto.Get(k); ok {
			for _, n := range []string{"tcp", "udp"} {
				if info.Net == n || info.Net == "both" {
					fmt.Printf("KITSUNE_PORT=%d/%s\n", ib.Port, n)
				}
			}
		}
		created++
	}
	if created == 0 {
		fmt.Println("✗  No connections were created")
		os.Exit(1)
	}
	u, err := db.CreateUser(*user, 0, 0, 0)
	if err != nil {
		fmt.Println("✗  Could not create user:", err)
		os.Exit(1)
	}
	_ = db.SyncMembership()
	fmt.Printf("KITSUNE_USER=%s\nKITSUNE_SUB=%s\n", u.Name, u.SubID)
}
