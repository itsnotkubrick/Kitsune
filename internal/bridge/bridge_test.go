package bridge

import (
	"strings"
	"testing"

	"kitsune/internal/db"
	"kitsune/internal/proto"
)

func TestCheckHost(t *testing.T) {
	good := []string{"203.0.113.7", "bridge.example.ru", "a-b.example.com"}
	bad := []string{"", "10.0.0.5", "127.0.0.1", "192.168.1.1", "0.0.0.0", "2001:db8::1", "no_dots", "a b.com", "http://x.ru", "x.ru/path", "-x.ru"}
	for _, h := range good {
		if err := CheckHost(h); err != nil {
			t.Errorf("%q должен подойти: %v", h, err)
		}
	}
	for _, h := range bad {
		if err := CheckHost(h); err == nil {
			t.Errorf("%q не должен подойти", h)
		}
	}
}

func TestValidateNames(t *testing.T) {
	if _, err := Validate([]Node{{Name: "", Host: "203.0.113.7"}}); err == nil {
		t.Error("пустое имя принято")
	}
	if _, err := Validate([]Node{{Name: "a#b", Host: "203.0.113.7"}}); err == nil {
		t.Error("имя с # принято: оно сломает ссылку подписки")
	}
	out, err := Validate([]Node{{Name: "Москва", Host: "203.0.113.7", Enabled: true}, {Name: "СПб", Host: "198.51.100.9"}})
	if err != nil || len(out) != 2 || out[0].ID == "" || out[0].ID == out[1].ID {
		t.Errorf("ожидали два узла с разными ID, получили %+v (%v)", out, err)
	}
}

func prof(k proto.Kind, host, sni string) *proto.Profile {
	return &proto.Profile{Kind: k, Name: "тег", Host: host, Port: 443, SNI: sni, U: db.User{}}
}

func TestExpandKeepsKeysAndName(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	if _, err := Save([]Node{{Name: "Узел", Host: "203.0.113.7", Enabled: true}, {Name: "выкл", Host: "198.51.100.9"}}); err != nil {
		t.Fatal(err)
	}
	in := []*proto.Profile{prof(proto.VlessReality, "vpn.example.net", "www.example.com"), prof(proto.AWG, "vpn.example.net", ""), prof(proto.VlessWS, "vpn.example.net", "")}
	out := Expand(in)
	// исходные три + копии для двух пересылаемых подключений (AWG в мост не идёт) через один включённый узел
	if len(out) != 5 {
		t.Fatalf("ожидали 5 профилей, получили %d", len(out))
	}
	r := out[3]
	if r.Host != "203.0.113.7" || r.SNI != "www.example.com" || !strings.HasSuffix(r.Name, " · Узел") {
		t.Errorf("копия через мост неверна: %+v", r)
	}
	ws := out[4]
	if ws.Host != "203.0.113.7" || ws.SNI != "vpn.example.net" {
		t.Errorf("для TLS-подключения имя сертификата должно остаться прежним адресом сервера: %+v", ws)
	}
	if in[0].Host != "vpn.example.net" {
		t.Error("исходный профиль изменён")
	}
}

func TestScript(t *testing.T) {
	s, err := Script("198.51.100.20", []Forward{{"tcp", 443}, {"udp", 8443}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"EXIT_IP='198.51.100.20'", "PORTS='tcp:443 udp:8443'", "nft --check --file", "nft --file", "ct original ip daddr", "policy drop", "kitsune-bridge.service"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, bad := range []string{"flush ruleset", "iptables -F", "curl ", "wget ", "eval "} {
		if strings.Contains(s, bad) {
			t.Errorf("unsafe command %q", bad)
		}
	}
	if _, err := Script("vpn.example.net", []Forward{{"tcp", 443}}); err == nil {
		t.Error("домен вместо IPv4 принят")
	}
	if _, err := Script("198.51.100.20", nil); err == nil {
		t.Error("пустой список портов принят")
	}
	if _, err := Script("198.51.100.20", []Forward{{"tcp", 70000}}); err == nil {
		t.Error("неверный порт принят")
	}
}

func TestNodeSNI(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	if _, err := Save([]Node{{Name: "Узел", Host: "203.0.113.7", Enabled: true, SNI: "  News.Example.COM "}}); err != nil {
		t.Fatal(err)
	}
	if got := List()[0].SNI; got != "news.example.com" {
		t.Errorf("имя приводится к нижнему регистру без пробелов: %q", got)
	}
	in := []*proto.Profile{prof(proto.VlessReality, "vpn.example.net", "www.example.com"), prof(proto.VlessWS, "vpn.example.net", "")}
	out := Expand(in)
	if out[2].SNI != "news.example.com" {
		t.Errorf("REALITY-копия должна взять имя узла: %+v", out[2])
	}
	if out[3].SNI != "vpn.example.net" {
		t.Errorf("TLS-копия имя узла не берёт: %+v", out[3])
	}
	if got := ExtraSNIs(); len(got) != 1 || got[0] != "news.example.com" {
		t.Errorf("сервер должен принимать имя узла: %v", got)
	}
	// выключенный узел имя не добавляет
	_, _ = Save([]Node{{Name: "Узел", Host: "203.0.113.7", Enabled: false, SNI: "news.example.com"}})
	if got := ExtraSNIs(); len(got) != 0 {
		t.Errorf("выключенный узел: %v", got)
	}
	for _, bad := range []string{"203.0.113.7", "нет пробелов в имени", "localhost", "a_b.example.com"} {
		if _, err := Validate([]Node{{Name: "x", Host: "203.0.113.7", SNI: bad}}); err == nil {
			t.Errorf("SNI %q принят", bad)
		}
	}
}
