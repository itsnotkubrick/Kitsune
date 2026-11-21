// Package masking подбирает сайты маскировки для REALITY: ищет в подсети сервера соседей с TLS 1.3 и HTTP/2.
package masking

import (
	"context"
	"crypto/tls"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type Candidate struct {
	Domain    string `json:"domain"`
	IP        string `json:"ip"`
	LatencyMS int    `json:"latency_ms"`
}

// Сайты, которые Xray не советует для маскировки, и свои имена сервера.
var bannedFragments = []string{"apple", "icloud", "microsoft", "cloudflare", "akamai", "fastly"}
var bannedSuffixes = []string{".ru", ".su", ".xn--p1ai", ".local", ".internal"}

func allowed(name string) bool {
	n := strings.ToLower(name)
	if n == "" || strings.ContainsAny(n, "*_ ") || !strings.Contains(n, ".") || net.ParseIP(n) != nil {
		return false
	}
	for _, f := range bannedFragments {
		if strings.Contains(n, f) {
			return false
		}
	}
	for _, s := range bannedSuffixes {
		if strings.HasSuffix(n, s) {
			return false
		}
	}
	return true
}

// Port – порт, на котором ищутся сайты (443; меняется только в тестах).
var Port = "443"

func handshake(ctx context.Context, ip, sni string, timeout time.Duration) (*tls.ConnectionState, time.Duration, error) {
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, Port))
	if err != nil {
		return nil, 0, err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout * 2))
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
	if sni != "" {
		cfg.ServerName = sni
	}
	c := tls.Client(raw, cfg)
	if err := c.HandshakeContext(ctx); err != nil {
		return nil, 0, err
	}
	st := c.ConnectionState()
	return &st, time.Since(start), nil
}

// Check проверяет, что сайт подходит для REALITY: TLS 1.3 и HTTP/2 по имени.
func Check(ctx context.Context, ip, domain string) (Candidate, bool) {
	st, lat, err := handshake(ctx, ip, domain, 2*time.Second)
	if err != nil || st.Version != tls.VersionTLS13 || st.NegotiatedProtocol != "h2" {
		return Candidate{}, false
	}
	return Candidate{Domain: domain, IP: ip, LatencyMS: int(lat.Milliseconds())}, true
}

// Scan просматривает соседние адреса /24 вокруг ip и возвращает подходящие сайты (до limit штук), быстрые первыми.
func Scan(ctx context.Context, ip string, limit int) []Candidate {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return nil
	}
	var mu sync.Mutex
	var found []Candidate
	seen := map[string]bool{}
	sem := make(chan struct{}, 16) // не больше 16 одновременных рукопожатий с чужими адресами
	var wg sync.WaitGroup
	for last := 1; last <= 254; last++ {
		if byte(last) == parsed[3] {
			continue
		}
		neighbor := net.IPv4(parsed[0], parsed[1], parsed[2], byte(last)).String()
		wg.Add(1)
		sem <- struct{}{}
		go func(addr string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			st, _, err := handshake(ctx, addr, "", 1500*time.Millisecond)
			if err != nil || len(st.PeerCertificates) == 0 {
				return
			}
			for _, name := range st.PeerCertificates[0].DNSNames {
				if !allowed(name) {
					continue
				}
				mu.Lock()
				dup := seen[name]
				seen[name] = true
				mu.Unlock()
				if dup {
					continue
				}
				if c, ok := Check(ctx, addr, name); ok {
					mu.Lock()
					found = append(found, c)
					mu.Unlock()
				}
			}
		}(neighbor)
	}
	wg.Wait()
	sort.Slice(found, func(i, j int) bool { return found[i].LatencyMS < found[j].LatencyMS })
	if limit > 0 && len(found) > limit {
		found = found[:limit]
	}
	return found
}
