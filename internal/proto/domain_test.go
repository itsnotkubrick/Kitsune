package proto

import "testing"

func TestNeedsDomain(t *testing.T) {
	cases := []struct {
		name string
		kind Kind
		s    Settings
		want bool
	}{
		{"naive без домена", Naive, Settings{}, true},
		{"naive с IP в SNI", Naive, Settings{SNI: "203.0.113.5"}, true},
		{"naive с доменом в SNI", Naive, Settings{SNI: "vpn.example.com"}, false},
		{"naive с доменом в адресе ссылок", Naive, Settings{ExternalHost: "vpn.example.com"}, false},
		{"naive с самоподписанным и без домена", Naive, Settings{CertMode: "self"}, true},
		{"naive acme, домен только в адресе ссылок", Naive, Settings{CertMode: "acme", ExternalHost: "vpn.example.com"}, true},
		{"naive acme с доменом в SNI", Naive, Settings{CertMode: "acme", SNI: "vpn.example.com"}, false},
		{"naive acme с IP в SNI и доменом в адресе", Naive, Settings{CertMode: "acme", SNI: "203.0.113.5", ExternalHost: "vpn.example.com"}, true},
		{"hysteria2 acme без SNI", Hysteria2, Settings{CertMode: "acme"}, true},
		{"hysteria2 acme с IPv6", Hysteria2, Settings{CertMode: "acme", SNI: "2001:db8::1"}, true},
		{"hysteria2 acme с доменом", Hysteria2, Settings{CertMode: "acme", SNI: "vpn.example.com"}, false},
		{"tuic самоподписанный", TUIC, Settings{CertMode: "self"}, false},
		{"vless ws acme без домена", VlessWS, Settings{CertMode: "acme"}, true},
		{"vless reality", VlessReality, Settings{}, false},
		{"shadowsocks", SS2022, Settings{CertMode: "acme"}, false},
		{"неизвестный тип", Kind("nope"), Settings{}, false},
	}
	for _, c := range cases {
		if got := NeedsDomain(c.kind, c.s); got != c.want {
			t.Errorf("%s: получили %v, ждали %v", c.name, got, c.want)
		}
	}
}
