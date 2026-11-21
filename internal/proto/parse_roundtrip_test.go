package proto

import "testing"

// Пароль из ссылки Trojan и Hysteria2 после разбора совпадает с исходным (в том числе «%», «@», «:»).
func TestParseLinkRoundTripPasswords(t *testing.T) {
	for _, k := range []Kind{TrojanGRPC, Hysteria2} {
		for _, pw := range []string{"plainPass123", "a@b", "a:b", "a@b:c@d:", "p%40x", "50%", "q?w#e/r", "юзер"} {
			in := inboundOf(t, k, 8443)
			u := testUser()
			u.Password = pw
			p, _ := NewProfile(in, u, Env{Host: "203.0.113.5"})
			pr, err := ParseLink(p.URI())
			if err != nil {
				t.Errorf("%s %q: %v", k, pw, err)
				continue
			}
			var got any
			if k == TrojanGRPC {
				got = pr.Outbound["settings"].(M)["servers"].([]M)[0]["password"]
			} else {
				got = pr.Outbound["streamSettings"].(M)["hysteriaSettings"].(M)["auth"]
			}
			if got != pw {
				t.Errorf("%s: %q -> %q (%s)", k, pw, got, p.URI())
			}
		}
	}
}

func TestParseLinkTrojanRawColon(t *testing.T) {
	p, err := ParseLink("trojan://user:pw@h.example.com:443?sni=h.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Outbound["settings"].(M)["servers"].([]M)[0]["password"]; got != "user:pw" {
		t.Errorf("пароль %q, ждали user:pw", got)
	}
	p, err = ParseLink("trojan://p%2540x@h.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Outbound["settings"].(M)["servers"].([]M)[0]["password"]; got != "p%40x" {
		t.Errorf("пароль %q, ждали p%%40x", got)
	}
}
