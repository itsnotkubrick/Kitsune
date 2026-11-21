package main

import (
	"log"
	"net"
	"os"
	"strings"
)

// trustedProxiesFromEnv читает KITSUNE_TRUSTED_PROXIES – список адресов или сетей через запятую
// (например 127.0.0.1,::1 для панели за локальным nginx). По умолчанию пусто: заголовкам
// X-Forwarded-For и X-Real-IP не верим, адрес клиента – это адрес TCP-соединения.
// Неверные записи пропускаются с предупреждением, а не расширяют доверие.
func trustedProxiesFromEnv() []string {
	return parseTrustedProxies(os.Getenv("KITSUNE_TRUSTED_PROXIES"))
}

func parseTrustedProxies(raw string) []string {
	out := []string{}
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if reason := badTrustedProxy(p); reason != "" {
			log.Printf("KITSUNE_TRUSTED_PROXIES: %q пропущено (%s)", p, reason)
			continue
		}
		out = append(out, p)
	}
	return out
}

// badTrustedProxy возвращает причину отказа или "". Слишком широкие сети отбрасываются:
// короче /8 для IPv4 и /16 для IPv6 (включая 0.0.0.0/N, ::/N, ::ffff:0.0.0.0/96 и 1.2.3.4/0).
// Сами записи по /8 принимаются, а набор из многих таких записей – осознанный выбор администратора.
func badTrustedProxy(p string) string {
	if !strings.Contains(p, "/") {
		if net.ParseIP(p) == nil {
			return "не адрес и не сеть"
		}
		return ""
	}
	ip, n, err := net.ParseCIDR(p)
	if err != nil {
		return "не адрес и не сеть"
	}
	ones, bits := n.Mask.Size()
	if ip.To4() != nil && bits == 128 { // IPv4 в записи ::ffff:a.b.c.d/N: префикс считается от 96
		ones -= 96
		bits = 32
	}
	if bits == 32 && ones < 8 || bits == 128 && ones < 16 {
		return "слишком широкая сеть, доверие почти всем адресам запрещено"
	}
	return ""
}

// Only the immediate TCP peer can supply forwarded headers.
func trustedProxy(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, proxy := range trustedProxiesFromEnv() {
		if _, subnet, err := net.ParseCIDR(proxy); err == nil {
			if subnet.Contains(ip) {
				return true
			}
		} else if ip.Equal(net.ParseIP(proxy)) {
			return true
		}
	}
	return false
}
