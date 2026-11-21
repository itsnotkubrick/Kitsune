package proto

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"kitsune/internal/db"
)

func testUser() db.User {
	return db.User{ID: 1, Name: "alice", UUID: "b7d246bd-b6bb-40f7-8f25-7c1eea66d15d", Password: "pw0123456789ab",
		SSKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), Enable: true, Vision: true}
}

func inboundOf(t *testing.T, k Kind, port int) db.Inbound {
	var s Settings
	if err := s.Fill(k); err != nil {
		t.Fatal(err)
	}
	s.SNI = firstNonEmpty(s.SNI, "vpn.example.com")
	return db.Inbound{ID: 1, Tag: string(k), Kind: string(k), Port: port, Enable: true, Settings: s.JSON()}
}

func TestEveryKindFillsAndBuilds(t *testing.T) {
	for _, info := range Catalog {
		var s Settings
		if err := s.Fill(info.ID); err != nil {
			t.Fatalf("%s: Fill: %v", info.ID, err)
		}
	}
}

func TestRealityLinkAndVisionToggle(t *testing.T) {
	in := inboundOf(t, VlessReality, 443)
	u := testUser()
	p, err := NewProfile(in, u, Env{Host: "203.0.113.5"})
	if err != nil {
		t.Fatal(err)
	}
	link := p.URI()
	parsed, err := url.Parse(link)
	if err != nil || parsed.Scheme != "vless" || parsed.Host != "203.0.113.5:443" {
		t.Fatalf("ссылка: %s (%v)", link, err)
	}
	q := parsed.Query()
	if q.Get("flow") != "xtls-rprx-vision" || q.Get("security") != "reality" || q.Get("pbk") == "" || q.Get("sid") == "" {
		t.Fatalf("параметры REALITY: %v", q)
	}
	u.Vision = false
	p2, _ := NewProfile(in, u, Env{Host: "203.0.113.5"})
	if strings.Contains(p2.URI(), "flow=") {
		t.Fatal("Vision выключен у пользователя – flow в ссылке быть не должно")
	}
	// сервер: у такого пользователя тоже нет flow
	x, err := BuildXray(in, []Cred{{Email: "alice@REALITY", User: u}}, Env{})
	if err != nil {
		t.Fatal(err)
	}
	cl := x["settings"].(M)["clients"].([]M)[0]
	if _, has := cl["flow"]; has {
		t.Fatal("сервер не должен требовать flow у пользователя без Vision")
	}
}

func TestSS2022KeySizesFollowMethod(t *testing.T) {
	for method, size := range map[string]int{"2022-blake3-aes-128-gcm": 16, "2022-blake3-aes-256-gcm": 32, "2022-blake3-chacha20-poly1305": 32} {
		var s Settings
		s.Method = method
		if err := s.Fill(SS2022); err != nil {
			t.Fatal(err)
		}
		raw, _ := base64.StdEncoding.DecodeString(s.ServerKey)
		if len(raw) != size {
			t.Fatalf("%s: ключ сервера %d байт, нужно %d", method, len(raw), size)
		}
		in := db.Inbound{ID: 1, Tag: "ss", Kind: string(SS2022), Port: 8388, Enable: true, Settings: s.JSON()}
		p, _ := NewProfile(in, testUser(), Env{Host: "h"})
		upw, _ := base64.StdEncoding.DecodeString(p.userSSKey())
		if len(upw) != size {
			t.Fatalf("%s: ключ пользователя %d байт, нужно %d", method, len(upw), size)
		}
	}
}

func TestSelfSignedTLSLinksCarryPin(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, k := range []Kind{VlessWS, TrojanGRPC, VmessWS, Hysteria2, TUIC} {
		in := inboundOf(t, k, 2053)
		p, err := NewProfile(in, testUser(), Env{Host: "203.0.113.5"})
		if err != nil {
			t.Fatal(err)
		}
		if !p.Insecure || p.Pin == "" {
			t.Fatalf("%s: самоподписанный сертификат – нужно закрепление отпечатка", k)
		}
		if p.URI() == "" {
			t.Fatalf("%s: пустая ссылка", k)
		}
	}
}

func TestOldSNIGrace(t *testing.T) {
	var s Settings
	s.SNI = "old.example.com"
	old := s.SNI
	s.SNI = "new.example.com"
	s.WithOldSNI(old, 4102444800) // 2100 год
	got := s.ActiveSNIs()
	if len(got) != 2 || got[0] != "new.example.com" || got[1] != "old.example.com" {
		t.Fatalf("ожидались новый и прежний сайты: %v", got)
	}
	s.OldSNIs = "gone.example.com:1"
	if len(s.ActiveSNIs()) != 1 {
		t.Fatal("истёкший прежний сайт не должен приниматься")
	}
}

func TestRoutedModeUsesPort443(t *testing.T) {
	in := inboundOf(t, VlessReality, 8443)
	env := Env{Host: "h", Single: true}
	p, _ := NewProfile(in, testUser(), env)
	if p.Port != 443 {
		t.Fatalf("в режиме «всё на 443» порт ссылки 443, получен %d", p.Port)
	}
	x, _ := BuildXray(in, nil, env)
	if x["listen"] != "127.0.0.1" || x["port"] != InnerPort(in.ID) {
		t.Fatalf("подключение должно слушать локально: %v %v", x["listen"], x["port"])
	}
}

func TestAWGPeerAllocation(t *testing.T) {
	a, err := NewAWGPeer("10.8.1.0/24", nil)
	if err != nil || a.IP != "10.8.1.2" {
		t.Fatalf("первый адрес .2: %+v %v", a, err)
	}
	b, _ := NewAWGPeer("10.8.1.0/24", []string{a.IP})
	if b.IP != "10.8.1.3" {
		t.Fatalf("второй адрес .3: %s", b.IP)
	}
	srv, _ := ServerAddr("10.8.1.0/24")
	if srv != "10.8.1.1/24" {
		t.Fatalf("адрес сервера: %s", srv)
	}
}

// «@» и «:» в пароле экранируются, и в ссылке остаётся ровно один «@» (граница логина и адреса).
func TestLinkPasswordWithAtAndColon(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, k := range []Kind{Hysteria2, TUIC, TrojanGRPC} {
		in := inboundOf(t, k, 8443)
		u := testUser()
		u.Password = "p@ss:w/rd#"
		p, err := NewProfile(in, u, Env{Host: "203.0.113.5"})
		if err != nil {
			t.Fatal(err)
		}
		link := p.URI()
		if n := strings.Count(strings.SplitN(link, "?", 2)[0], "@"); n != 1 {
			t.Errorf("%s: «@» в ссылке %d раз: %s", k, n, link)
		}
		pu, err := url.Parse(link)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		got, _ := pu.User.Password()
		if pw := firstNonEmpty(got, pu.User.Username()); pw != u.Password {
			t.Errorf("%s: пароль в ссылке %q", k, pw)
		}
	}
}

func TestClientHeaderKey(t *testing.T) {
	var s Settings
	if err := s.Fill(AWG3); err != nil {
		t.Fatal(err)
	}
	if len(s.HeaderKey) != 64 {
		t.Fatalf("в настройках ключ должен быть hex на 64 символа: %q", s.HeaderKey)
	}
	k := ClientHeaderKey(s.HeaderKey)
	raw, err := base64.StdEncoding.DecodeString(k)
	if err != nil || len(raw) != 32 || len(k) != 44 {
		t.Fatalf("клиентский ключ не base64 на 32 байта: %q (%v)", k, err)
	}
	if hex.EncodeToString(raw) != s.HeaderKey {
		t.Fatal("клиентский ключ после перевода в hex не равен серверному")
	}
	if ClientHeaderKey(k) != k {
		t.Fatal("ключ в base64 должен возвращаться без изменений")
	}
	// сохранённый ранее hex не перегенерируется
	old := Settings{HeaderKey: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}
	if err := old.Fill(AWG3); err != nil || old.HeaderKey != "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" {
		t.Fatalf("ключ из настроек изменился: %q (%v)", old.HeaderKey, err)
	}
}

func TestAWGConfigHeaderKeyBase64(t *testing.T) {
	var s Settings
	if err := s.Fill(AWG3); err != nil {
		t.Fatal(err)
	}
	peer, _ := NewAWGPeer(s.Subnet, nil)
	conf := (&Profile{AWG: &peer, S: s, Host: "203.0.113.5", Port: 51822}).AWGConfig()
	want := "HeaderProtectionKey = " + ClientHeaderKey(s.HeaderKey) + "\n"
	if !strings.Contains(conf, want) || strings.Contains(conf, s.HeaderKey) {
		t.Fatalf("в конфиге ключ должен быть base64:\n%s", conf)
	}
}

// unpackAmneziaURI распаковывает vpn:// (4 байта длины + zlib в base64url) в JSON.
func unpackAmneziaURI(t *testing.T, uri string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(uri, "vpn://"))
	if err != nil || len(raw) < 5 {
		t.Fatalf("vpn:// не раскодируется: %v", err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw[4:]))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(zr)
	if err != nil || int(binary.BigEndian.Uint32(raw[:4])) != len(body) {
		t.Fatalf("длина в заголовке не совпадает с данными: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestAmneziaURIv31(t *testing.T) {
	for _, kind := range []Kind{AWG3, AWG} {
		var s Settings
		if err := s.Fill(kind); err != nil {
			t.Fatal(err)
		}
		peer, _ := NewAWGPeer(s.Subnet, nil)
		root := unpackAmneziaURI(t, (&Profile{AWG: &peer, S: s, Host: "203.0.113.5", Port: 51822}).AmneziaURI())
		block := root["containers"].([]any)[0].(map[string]any)["awg"].(map[string]any)
		var last map[string]any
		if err := json.Unmarshal([]byte(block["last_config"].(string)), &last); err != nil {
			t.Fatal(err)
		}
		for name, m := range map[string]map[string]any{"awg": block, "last_config": last} {
			key, has := m["HeaderProtectionKey"]
			if kind == AWG {
				if has || m["protocol_version"] != nil {
					t.Fatalf("%s: у обычной AWG нет ключа и версии 3.1", name)
				}
				continue
			}
			if key != ClientHeaderKey(s.HeaderKey) || m["protocol_version"] != "3.1" {
				t.Fatalf("%s: ключ %v, версия %v", name, key, m["protocol_version"])
			}
			for _, k := range []string{"Jc", "S1", "S2", "S3", "S4", "H1", "H4"} {
				if m[k] == nil {
					t.Fatalf("%s: нет %s", name, k)
				}
			}
		}
		wantC := "amnezia-awg"
		if kind == AWG3 {
			wantC = "amnezia-awg2"
		}
		if root["defaultContainer"] != wantC || root["containers"].([]any)[0].(map[string]any)["container"] != wantC {
			t.Fatalf("контейнер: %v", root["defaultContainer"])
		}
		wantDNS := "DNS = " + s.DNS + "\n"
		if kind == AWG3 {
			wantDNS = "DNS = " + s.DNS + ", 8.8.8.8\n"
		}
		if !strings.Contains(last["config"].(string), wantDNS) {
			t.Fatalf("в config DNS: у 3.1 пара, у обычной AWG один адрес:\n%s", last["config"])
		}
		if kind == AWG3 && !strings.Contains(last["config"].(string), "HeaderProtectionKey = "+ClientHeaderKey(s.HeaderKey)+"\n") {
			t.Fatal("в config нет ключа в base64")
		}
	}
}

func TestClashAWG3(t *testing.T) {
	var s Settings
	if err := s.Fill(AWG3); err != nil {
		t.Fatal(err)
	}
	s.I1, s.I3 = "<b 0xc0000000><r 16>", "<r 8>"
	peer, _ := NewAWGPeer(s.Subnet, nil)
	m := (&Profile{Name: "awg31", Kind: AWG3, AWG: &peer, S: s, Host: "203.0.113.5", Port: 51822}).Clash()
	if m == nil || m["type"] != "wireguard" || m["public-key"] != s.PublicKey || m["ip"] != peer.IP {
		t.Fatalf("прокси AWG 3.1 не собран: %v", m)
	}
	opt, ok := m["amnezia-wg-option"].(M)
	if !ok {
		t.Fatalf("нет amnezia-wg-option: %v", m)
	}
	want := M{"version": 3, "jc": 4, "jmin": 40, "jmax": 70, "s1": 15, "s2": 68, "s3": 20, "s4": 20,
		"h1": "1", "h2": "2", "h3": "3", "h4": "4", "i1": "<b 0xc0000000><r 16>", "i3": "<r 8>",
		"header-protection-key": ClientHeaderKey(s.HeaderKey)}
	if !reflect.DeepEqual(opt, want) {
		t.Fatalf("amnezia-wg-option:\n got %v\nwant %v", opt, want)
	}
	if m["persistent-keepalive"] != 25 {
		t.Fatalf("persistent-keepalive: %v", m["persistent-keepalive"])
	}
	raw, err := base64.StdEncoding.DecodeString(opt["header-protection-key"].(string))
	if err != nil || len(raw) != 32 {
		t.Fatalf("header-protection-key не base64 на 32 байта: %v", err)
	}
}

func TestClashAWGClassicUnchanged(t *testing.T) {
	var s Settings
	if err := s.Fill(AWG); err != nil {
		t.Fatal(err)
	}
	peer, _ := NewAWGPeer(s.Subnet, nil)
	m := (&Profile{Name: "awg", Kind: AWG, AWG: &peer, S: s, Host: "203.0.113.5", Port: 51821}).Clash()
	if _, has := m["persistent-keepalive"]; has {
		t.Fatalf("persistent-keepalive: %v", m["persistent-keepalive"])
	}
	opt := m["amnezia-wg-option"].(M)
	want := M{"jc": 4, "jmin": 40, "jmax": 70, "s1": 15, "s2": 68, "h1": 1, "h2": 2, "h3": 3, "h4": 4}
	if !reflect.DeepEqual(opt, want) {
		t.Fatalf("amnezia-wg-option: %v", opt)
	}
}

func TestAmneziaURITypes(t *testing.T) {
	var s Settings
	if err := s.Fill(AWG3); err != nil {
		t.Fatal(err)
	}
	s.I1 = "<r 16>"
	peer, _ := NewAWGPeer(s.Subnet, nil)
	root := unpackAmneziaURI(t, (&Profile{Kind: AWG3, AWG: &peer, S: s, Host: "203.0.113.5", Port: 51822}).AmneziaURI())
	block := root["containers"].([]any)[0].(map[string]any)["awg"].(map[string]any)
	var last map[string]any
	if err := json.Unmarshal([]byte(block["last_config"].(string)), &last); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "HeaderProtectionKey", "protocol_version", "port", "transport_proto"} {
		if _, ok := block[k].(string); !ok {
			t.Fatalf("awg.%s должно быть строкой: %#v", k, block[k])
		}
	}
	for _, k := range []string{"Jc", "S4", "H4", "I1", "HeaderProtectionKey", "mtu", "persistent_keep_alive"} {
		if _, ok := last[k].(string); !ok {
			t.Fatalf("last_config.%s должно быть строкой: %#v", k, last[k])
		}
	}
	if n, ok := last["port"].(float64); !ok || n != 51822 {
		t.Fatalf("last_config.port должен быть числом: %#v", last["port"])
	}
	if a, ok := last["allowed_ips"].([]any); !ok || len(a) != 2 {
		t.Fatalf("allowed_ips должен быть массивом: %#v", last["allowed_ips"])
	}
	raw, err := base64.StdEncoding.DecodeString(block["HeaderProtectionKey"].(string))
	if err != nil || hex.EncodeToString(raw) != s.HeaderKey || last["HeaderProtectionKey"] != block["HeaderProtectionKey"] {
		t.Fatal("ключ в vpn:// не равен серверному")
	}
}

func TestAWG31ConfTimings(t *testing.T) {
	var s Settings
	if err := s.Fill(AWG3); err != nil {
		t.Fatal(err)
	}
	peer, _ := NewAWGPeer(s.Subnet, nil)
	conf := (&Profile{Name: "a", Kind: AWG3, AWG: &peer, S: s, Host: "203.0.113.5", Port: 51822}).AWGConfig()
	for _, want := range []string{"RekeyAfterTime = 100-120\n", "RekeyTimeout = 3-8\n", "RejectAfterTime = 150-180\n",
		"KeepaliveTimeout = 7-13\n", "MaxHandshakeAttempts = 15-20\n", "ContentPaddingAddition = 10-100\n"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("в .conf 3.1 нет %q:\n%s", want, conf)
		}
	}
	var c Settings
	if err := c.Fill(AWG); err != nil {
		t.Fatal(err)
	}
	cp, _ := NewAWGPeer(c.Subnet, nil)
	classic := (&Profile{Name: "c", Kind: AWG, AWG: &cp, S: c, Host: "203.0.113.5", Port: 51821}).AWGConfig()
	if strings.Contains(classic, "RekeyAfterTime") || strings.Contains(classic, "HeaderProtectionKey") {
		t.Fatalf("в .conf обычной AWG не должно быть полей 3.1:\n%s", classic)
	}
}

func TestIsRange(t *testing.T) {
	for v, want := range map[string]bool{"25": true, "25-35": true, " 7-13 ": true, "": false, "-5": false, "5-": false, "a": false, "1-2-3": false, "1\nX = 2": false} {
		if IsRange(v) != want {
			t.Errorf("IsRange(%q) = %v", v, !want)
		}
	}
	if firstInt("25-35", 0) != 25 || firstInt("x", 7) != 7 {
		t.Fatal("firstInt")
	}
}
