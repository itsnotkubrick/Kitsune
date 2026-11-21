package proto

import (
	"encoding/json"
	"strings"
	"testing"

	"kitsune/internal/db"
)

func norm(v any) string { b, _ := json.Marshal(v); return string(b) }

// Всё, что панель сама отдаёт клиентам, должно разбираться обратно в то же исходящее, которым панель проверяет себя.
func TestParseLinkRoundTripsOwnLinks(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, k := range []Kind{VlessReality, VlessXHTTP, VlessWS, TrojanGRPC, VmessWS, SS2022, Hysteria2} {
		in := inboundOf(t, k, 2053)
		p, err := NewProfile(in, testUserFor(), Env{Host: "203.0.113.5"})
		if err != nil {
			t.Fatal(err)
		}
		want := p.XrayOutbound()
		got, err := ParseLink(p.URI())
		if err != nil {
			t.Fatalf("%s: %v (%s)", k, err, p.URI())
		}
		if got.Server != "203.0.113.5" || got.Port != 2053 {
			t.Fatalf("%s: адрес %s:%d", k, got.Server, got.Port)
		}
		if got.Outbound["protocol"] != want["protocol"] {
			t.Fatalf("%s: протокол %v, ожидался %v", k, got.Outbound["protocol"], want["protocol"])
		}
		// ключевые параметры потока совпадают с рабочим исходящим
		for _, key := range []string{"network", "security"} {
			g, _ := got.Outbound["streamSettings"].(M)
			w, _ := want["streamSettings"].(M)
			if g[key] != w[key] {
				t.Fatalf("%s: %s = %v, ожидалось %v\nполучено: %s\nожидалось: %s", k, key, g[key], w[key], norm(got.Outbound), norm(want))
			}
		}
		if k == VlessReality {
			g := got.Outbound["streamSettings"].(M)["realitySettings"].(M)
			w := want["streamSettings"].(M)["realitySettings"].(M)
			for _, key := range []string{"serverName", "password", "shortId", "fingerprint"} {
				if g[key] != w[key] {
					t.Fatalf("REALITY %s: %v != %v", key, g[key], w[key])
				}
			}
			if !strings.Contains(norm(got.Outbound), "xtls-rprx-vision") {
				t.Fatal("flow потерян")
			}
		}
		if k == Hysteria2 || k == VlessWS || k == TrojanGRPC {
			if !strings.Contains(norm(got.Outbound), "pinnedPeerCertSha256") {
				t.Fatalf("%s: отпечаток сертификата потерян: %s", k, norm(got.Outbound))
			}
		}
		if k == SS2022 {
			gs := got.Outbound["settings"].(M)["servers"].([]M)[0]
			ws := want["settings"].(M)["servers"].([]M)[0]
			if gs["method"] != ws["method"] || gs["password"] != ws["password"] {
				t.Fatalf("ss: %v != %v", gs, ws)
			}
		}
	}
}

func TestParseLinkErrors(t *testing.T) {
	for _, bad := range []string{"", "hello", "vless://", "vless://id@host", "vless://id@host:99999?security=tls", "ftp://a@b:1", "vmess://%%%", "ss://zzzz",
		"vless://id@h:443?type=kcp", "vless://id@h:443?security=weird"} {
		if _, err := ParseLink(bad); err == nil {
			t.Errorf("%q должна отклоняться", bad)
		}
	}
	if p, err := ParseLink("ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#мой"); err != nil || p.Name != "мой" || p.Outbound["protocol"] != "shadowsocks" {
		t.Fatalf("классический ss: %v %v", p, err)
	}
	if p, err := ParseLink("trojan://pw%20x@h.example.com:443?sni=h.example.com&type=ws&path=%2Fws"); err != nil || p.Outbound["streamSettings"].(M)["security"] != "tls" {
		t.Fatalf("trojan: %v %v", p, err)
	}
}

func testUserFor() db.User { return testUser() }

// Karing 1.2.25: «insecure is not supported on naive outbound» – с самоподписанным сертификатом узла быть не должно.
func TestNaiveNotInSingboxWhenSelfSigned(t *testing.T) {
	t.Chdir(t.TempDir())
	in := inboundOf(t, Naive, 8445)
	p, err := NewProfile(in, testUser(), Env{Host: "203.0.113.5"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Insecure && p.SingBox() != nil {
		t.Fatal("naive с самоподписанным сертификатом не должен попадать в sing-box")
	}
	p.Insecure = false
	if p.SingBox() == nil {
		t.Fatal("naive с доверенным сертификатом должен быть в sing-box")
	}
	if tls, _ := p.SingBox()["tls"].(M); tls["insecure"] != nil {
		t.Fatal("insecure в naive быть не должно")
	}
}

func TestNaiveUsesDomainAsHostWithTrustedCert(t *testing.T) {
	t.Chdir(t.TempDir())
	var s Settings
	if err := s.Fill(Naive); err != nil {
		t.Fatal(err)
	}
	s.SNI, s.CertMode = "vpn.example.com", "acme"
	in := db.Inbound{ID: 1, Tag: "Naive", Kind: string(Naive), Port: 8445, Enable: true, Settings: s.JSON()}
	p, err := NewProfile(in, testUser(), Env{Host: "203.0.113.5"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "vpn.example.com" || p.Insecure {
		t.Fatalf("для Naive с доверенным сертификатом нужен домен: host=%q insecure=%v", p.Host, p.Insecure)
	}
	// у остальных протоколов адрес остаётся IP-адресом сервера
	in2 := inboundOf(t, VlessWS, 2053)
	p2, _ := NewProfile(in2, testUser(), Env{Host: "203.0.113.5"})
	if p2.Host != "203.0.113.5" {
		t.Fatalf("адрес других протоколов менять нельзя: %q", p2.Host)
	}
}
