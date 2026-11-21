package importer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kitsune/internal/proto"
)

// marzbanConfig – config.json Xray в виде, как его хранит Marzban: у подключений пустые списки клиентов.
func marzbanConfig(t *testing.T) string {
	priv, _, _ := proto.RealityKeys()
	cfg := m{"log": m{"loglevel": "warning"}, "inbounds": []m{
		{"tag": "VLESS TCP REALITY", "listen": "0.0.0.0", "port": 443, "protocol": "vless",
			"settings": m{"clients": []m{}, "decryption": "none"},
			"streamSettings": m{"network": "tcp", "security": "reality", "realitySettings": m{
				"dest": "www.example.com:443", "serverNames": []string{"www.example.com"}, "privateKey": priv, "shortIds": []string{"ab12cd34"}}}},
		{"tag": "TROJAN WS", "port": 8081, "protocol": "trojan", "settings": m{"clients": []m{}},
			"streamSettings": m{"network": "ws", "security": "none"}},
		{"tag": "API_INBOUND", "listen": "127.0.0.1", "port": 62789, "protocol": "dokodemo-door", "settings": m{"address": "127.0.0.1"}},
		{"tag": "VMESS WS TLS", "port": 2087, "protocol": "vmess", "settings": m{"clients": []m{}},
			"streamSettings": m{"network": "ws", "security": "tls", "wsSettings": m{"path": "/vm"}, "tlsSettings": m{"certificates": []m{{"certificateFile": "/var/lib/marzban/certs/f.pem", "keyFile": "/var/lib/marzban/certs/k.pem"}}}}},
		{"tag": "SS", "port": 1080, "protocol": "shadowsocks", "settings": m{"clients": []m{}, "network": "tcp,udp"}},
	}}
	p := filepath.Join(t.TempDir(), "xray_config.json")
	if err := os.WriteFile(p, []byte(jsonOf(t, cfg)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadXrayConfigMarzban(t *testing.T) {
	data, err := ReadXrayConfig(marzbanConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]SrcInbound{}
	for _, i := range data.Inbounds {
		by[i.Name] = i
	}
	if r := by["VLESS TCP REALITY"]; r.Kind != proto.VlessReality || r.Port != 443 || r.Settings.SNI != "www.example.com" ||
		r.Settings.PrivateKey == "" || r.Settings.PublicKey == "" || r.Settings.ShortIDs != "ab12cd34" {
		t.Errorf("reality: %+v", r)
	}
	if v := by["VMESS WS TLS"]; v.Kind != proto.VmessWS || v.Settings.CertFile != "/var/lib/marzban/certs/f.pem" || v.Settings.Path != "/vm" {
		t.Errorf("vmess: %+v", v)
	}
	if v := by["TROJAN WS"]; v.Kind != "" || v.SkipReason == "" {
		t.Errorf("trojan ws не поддерживается: %+v", v)
	}
	if v := by["API_INBOUND"]; v.Kind != "" || v.SkipReason == "" {
		t.Errorf("служебное подключение должно пропускаться: %+v", v)
	}
	if v := by["SS"]; v.Kind != "" {
		t.Errorf("shadowsocks без ключа сервера: %+v", v)
	}
	if len(data.Users) != 0 {
		t.Errorf("пользователей быть не должно: %+v", data.Users)
	}
}

func TestMarzbanWithConfigRun(t *testing.T) {
	data, err := ReadMarzban(marzbanFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ReadXrayConfig(marzbanConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	data.WithConfig(cfg)
	k := openKitsune(t)
	rep, err := Run(k, data, opts(true, false))
	if err != nil {
		t.Fatal(err)
	}
	if rep.InSum.Create != 2 {
		t.Fatalf("подключения: %+v %+v", rep.InSum, rep.Inbounds)
	}
	if n := count(t, k, "inbounds"); n != 2 {
		t.Fatalf("в базе %d подключений", n)
	}
	// Трафик пользователей распределяется по созданным подключениям.
	if count(t, k, "clients") == 0 {
		t.Error("трафик пользователей не записан")
	}
	if strings.Contains(jsonOf(t, rep), "PRIVATE") {
		t.Error("секрет в отчёте")
	}
}

func TestXrayConfigWithClients(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	cfg := m{"inbounds": []m{{"tag": "in", "port": 8443, "protocol": "hysteria", "settings": m{"version": 2, "clients": []m{{"auth": "pw-1", "email": "kate"}}},
		"streamSettings": m{"network": "hysteria", "security": "tls"}}}}
	os.WriteFile(p, []byte(jsonOf(t, cfg)), 0o600)
	data, err := ReadXrayConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Users) != 1 || data.Users[0].Password != "pw-1" || data.Inbounds[0].Kind != proto.Hysteria2 {
		t.Fatalf("%+v %+v", data.Users, data.Inbounds)
	}
}

func TestXrayConfigBad(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	for name, p := range map[string]string{
		"empty":   write("b.json", `{"inbounds": []}`),
		"junk":    write("c.json", "not json"),
		"dir":     dir,
		"missing": filepath.Join(dir, "none.json"),
	} {
		if _, err := ReadXrayConfig(p); err == nil {
			t.Errorf("%s: ждали ошибку", name)
		}
	}
	big := filepath.Join(dir, "big.json")
	os.WriteFile(big, []byte(strings.Repeat(" ", MaxConfigSize+1)), 0o600)
	if _, err := ReadXrayConfig(big); err == nil || !strings.Contains(err.Error(), "больше") {
		t.Errorf("большой файл: %v", err)
	}
}

func TestXrayConfigLocalAddresses(t *testing.T) {
	cfg := `{"inbounds":[
	 {"tag":"a","port":443,"protocol":"vless","settings":{"clients":[]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverNames":["localhost"],"privateKey":"x"}}},
	 {"tag":"b","port":444,"protocol":"vless","settings":{"clients":[]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverNames":["ok.example.com"],"target":"127.0.0.1:8080","privateKey":"x"}}},
	 {"tag":"c","listen":"127.0.0.1","port":445,"protocol":"vless","settings":{"clients":[]},"streamSettings":{"network":"tcp","security":"reality"}}]}`
	data, err := parseXrayConfig([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if data.Inbounds[0].Kind != "" || !strings.Contains(data.Inbounds[0].SkipReason, "локальн") {
		t.Errorf("a: %+v", data.Inbounds[0])
	}
	if b := data.Inbounds[1]; b.Kind == "" || b.Settings.Target != "" || len(b.Warnings) == 0 {
		t.Errorf("b: локальный target должен сбрасываться: %+v", b)
	}
	if c := data.Inbounds[2]; c.Kind != "" {
		t.Errorf("c: слушает только локально: %+v", c)
	}
}
