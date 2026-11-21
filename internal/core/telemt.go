package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"kitsune/internal/db"
	"kitsune/internal/proto"
)

func TelemtBinary() string { return FindBinary("telemt") }

func tomlStr(s string) string { return strconv.Quote(s) }

// BuildTelemtConfig собирает config.toml для telemt (формат из документации проекта): у каждого пользователя личный
// секрет, а лимит трафика, срок и число устройств telemt применяет сам.
func BuildTelemtConfig(ib db.Inbound, users []db.User, env proto.Env, dataDir string) string {
	s := proto.ParseSettings(ib.Settings)
	port := ib.Port
	listen := firstNonEmpty(s.Listen, "0.0.0.0")
	linkPort := port
	if proto.Routed(ib, env) {
		listen, port = "127.0.0.1", proto.InnerPort(ib.ID)
		linkPort = 443
	}
	var sb strings.Builder
	cs := LoadCoreSettings().Telemt
	fmt.Fprintf(&sb, "[general]\nuse_middle_proxy = %t\nlog_level = %s\n\n", cs.UseMiddleProxy, tomlStr(cs.LogLevel))
	sb.WriteString("[general.modes]\nclassic = false\nsecure = false\ntls = true\n\n")
	sb.WriteString("[general.links]\nshow = \"*\"\n")
	if env.Host != "" {
		fmt.Fprintf(&sb, "public_host = %s\npublic_port = %d\n", tomlStr(firstNonEmpty(s.ExternalHost, env.Host)), linkPort)
	}
	if cs.IPv6 || cs.Prefer != 4 {
		fmt.Fprintf(&sb, "\n[network]\nipv6 = %t\nprefer = %d\n", cs.IPv6, cs.Prefer)
	}
	maxConn := ""
	if cs.MaxConnections != 10000 {
		maxConn = fmt.Sprintf("max_connections = %d\n", cs.MaxConnections)
	}
	fmt.Fprintf(&sb, "\n[server]\nport = %d\n%s\n[server.api]\nenabled = false\n\n[[server.listeners]]\nip = %s\n\n", port, maxConn, tomlStr(listen))
	fmt.Fprintf(&sb, "[censorship]\ntls_domain = %s\nmask = true\ntls_emulation = true\ntls_front_dir = %s\n\n",
		tomlStr(firstNonEmpty(s.FakeTLS, "www.cloudflare.com")), tomlStr(filepath.Join(dataDir, "tlsfront")))

	gm := db.GroupMap()
	var active []db.User
	for _, u := range users {
		if u.Active() && db.Allowed(gm, u, ib.ID) {
			active = append(active, u)
		}
	}
	sb.WriteString("[access.users]\n")
	salt := db.MTProtoSalt()
	for _, u := range active {
		sec := proto.MTProtoUserSecret(salt, u.UUID)
		if sec == "" { // соли нет – личные секреты не выдаём
			continue
		}
		fmt.Fprintf(&sb, "%s = %s\n", tomlStr(u.Name), tomlStr(sec))
	}
	section := func(name string, line func(u db.User) string) {
		var lines []string
		for _, u := range active {
			if l := line(u); l != "" {
				lines = append(lines, l)
			}
		}
		if len(lines) > 0 {
			fmt.Fprintf(&sb, "\n[access.%s]\n%s\n", name, strings.Join(lines, "\n"))
		}
	}
	section("user_data_quota", func(u db.User) string {
		if u.TrafficLimit <= 0 {
			return ""
		}
		left := u.TrafficLimit - u.UsedTraffic
		if left < 1 {
			left = 1
		}
		return fmt.Sprintf("%s = %d", tomlStr(u.Name), left)
	})
	section("user_expirations", func(u db.User) string {
		if u.ExpiryTime <= 0 {
			return ""
		}
		return fmt.Sprintf("%s = %s", tomlStr(u.Name), tomlStr(time.UnixMilli(u.ExpiryTime).UTC().Format(time.RFC3339)))
	})
	section("user_max_unique_ips", func(u db.User) string {
		if u.IPLimit <= 0 {
			return ""
		}
		return fmt.Sprintf("%s = %d", tomlStr(u.Name), u.IPLimit)
	})
	return sb.String()
}

// applyTelemt запускает telemt для подключения MTProto с движком telemt.
func applyTelemt(ib db.Inbound, users []db.User) error {
	bin := TelemtBinary()
	if bin == "" {
		return fmt.Errorf("telemt не установлен (нужен для MTProto с личными секретами, только Linux)")
	}
	if db.MTProtoSalt() == "" {
		return fmt.Errorf("соль MTProto недоступна (база не даёт записать): личные секреты не выдаются, telemt не запущен")
	}
	dir, _ := filepath.Abs(filepath.Join("run", "telemt-"+strconv.Itoa(ib.ID)))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(BuildTelemtConfig(ib, users, PublicEnv(), dir)), 0o600); err != nil {
		return err
	}
	name := "tlm-" + strconv.Itoa(ib.ID)
	return mtgProc(name).Start(bin, []string{path}, nil, dir)
}
