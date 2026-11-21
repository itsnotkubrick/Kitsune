package proto

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// Без домена (в SNI пусто, адрес сервера – IP) имя в профили не попадает: ни в ссылки, ни в готовые конфиги.
func TestNoIPInServerName(t *testing.T) {
	const ip = "203.0.113.5"
	for _, k := range []Kind{VlessWS, VmessWS, TrojanGRPC, Hysteria2, TUIC, Naive} {
		in := inboundOf(t, k, 8443)
		s := ParseSettings(in.Settings)
		s.SNI = ""
		in.Settings = s.JSON()
		p, err := NewProfile(in, testUser(), Env{Host: ip})
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		if p.SNI != "" {
			t.Errorf("%s: SNI %q, ждали пусто", k, p.SNI)
		}
		if link := p.URI(); k != VmessWS {
			if u, err := url.Parse(link); err == nil {
				for _, key := range []string{"sni", "host"} {
					if u.Query().Has(key) {
						t.Errorf("%s: в ссылке есть %s: %s", k, key, link)
					}
				}
			}
		}
		for name, v := range map[string]any{"mihomo": p.Clash(), "singbox": p.SingBox(), "xray": p.XrayOutbound()} {
			if v == nil {
				continue
			}
			if b := mustJSON(t, v); strings.Contains(b, `"`+ip+`"`) && !strings.Contains(b, `"address":"`+ip+`"`) && !strings.Contains(b, `"server":"`+ip+`"`) {
				t.Errorf("%s/%s: IP попал не только в адрес сервера: %s", k, name, b)
			}
		}
	}
}

func TestServerNameKeepsDomain(t *testing.T) {
	s := Settings{SNI: "vpn.example.com"}
	if got := s.serverName(Env{Host: "203.0.113.5"}); got != "vpn.example.com" {
		t.Errorf("получили %q", got)
	}
	if got := (Settings{}).serverName(Env{Host: "vpn.example.com"}); got != "vpn.example.com" {
		t.Errorf("домен вместо адреса: получили %q", got)
	}
	for _, h := range []string{"203.0.113.5", "2001:db8::1", "[2001:db8::1]"} {
		if got := (Settings{SNI: h}).serverName(Env{}); got != "" {
			t.Errorf("IP %q в SNI: получили %q", h, got)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
