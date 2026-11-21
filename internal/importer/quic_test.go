package importer

import (
	"strings"
	"testing"

	"kitsune/internal/proto"
)

// quicFixture – база 3x-ui с Hysteria 2 и TUIC.
func quicFixture(t *testing.T) string {
	d, p := newFile(t)
	mustExec(t, d, `CREATE TABLE inbounds (id INTEGER PRIMARY KEY, remark TEXT, enable NUMERIC, listen TEXT, port INT, protocol TEXT, settings TEXT, stream_settings TEXT, tag TEXT)`)
	hyStream := m{"network": "hysteria", "security": "tls",
		"tlsSettings":      m{"serverName": "hy.example.com", "certificates": []m{{"certificateFile": "/etc/ssl/hy.crt", "keyFile": "/etc/ssl/hy.key"}}},
		"hysteriaSettings": m{"version": 2, "udpIdleTimeout": 90, "masquerade": m{"type": "proxy", "url": "https://news.example.org"}},
		"finalmask":        m{"udp": []m{{"type": "salamander", "settings": m{"password": "obfs-secret"}}}, "quicParams": m{"brutalUp": "100 mbps", "brutalDown": "200 mbps"}}}
	mustExec(t, d, `INSERT INTO inbounds VALUES (1, 'HY', 1, '', 8443, 'hysteria', ?, ?, 'in-8443')`,
		jsonOf(t, m{"version": 2, "clients": []m{
			{"auth": "hy-pass-1", "email": "ann", "subId": "subAnn", "totalGB": 5 << 30, "expiryTime": 1800000000000, "enable": true},
			{"auth": "hy-pass-2", "email": "ben", "subId": "subBen", "enable": true},
		}}), jsonOf(t, hyStream))
	mustExec(t, d, `INSERT INTO inbounds VALUES (2, 'TU', 1, '', 8444, 'tuic', ?, ?, 'in-8444')`,
		jsonOf(t, m{"congestion_control": "cubic", "udp_relay_mode": "quic", "zero_rtt_handshake": true, "heartbeat": "15s", "auth_timeout": "5s",
			"tls":   m{"server_name": "tu.example.com", "certificate_path": "/etc/ssl/tu.crt", "key_path": "/etc/ssl/tu.key"},
			"users": []m{{"uuid": uuidA, "password": "tuic-pass", "name": "ann-tuic", "subId": "subAnn"}}}), `{}`)
	mustExec(t, d, `INSERT INTO inbounds VALUES (3, 'HY1', 1, '', 8445, 'hysteria', '{"version":1,"clients":[]}', '{}', 'in-8445')`)
	return p
}

func TestHysteria2AndTUICRead(t *testing.T) {
	data, err := Read3XUI(quicFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]SrcInbound{}
	for _, i := range data.Inbounds {
		in[i.Name] = i
	}
	h := in["HY"]
	if h.Kind != proto.Hysteria2 || h.Port != 8443 {
		t.Fatalf("hysteria2: %+v", h)
	}
	s := h.Settings
	if s.SNI != "hy.example.com" || s.CertMode != "custom" || s.CertFile != "/etc/ssl/hy.crt" || s.KeyFile != "/etc/ssl/hy.key" ||
		s.ObfsPassword != "obfs-secret" || s.UpMbps != "100" || s.DownMbps != "200" || s.UDPIdleTimeout != "90" || s.Masquerade != "https://news.example.org" {
		t.Errorf("настройки hysteria2: %+v", s)
	}
	tu := in["TU"]
	if tu.Kind != proto.TUIC || tu.Port != 8444 {
		t.Fatalf("tuic: %+v", tu)
	}
	if s := tu.Settings; s.Congestion != "cubic" || s.UDPRelayMode != "quic" || s.ZeroRTT != "true" || s.Heartbeat != "15s" || s.AuthTimeout != "5s" ||
		s.SNI != "tu.example.com" || s.CertFile != "/etc/ssl/tu.crt" {
		t.Errorf("настройки tuic: %+v", s)
	}
	if o := in["HY1"]; o.Kind != "" || !strings.Contains(o.SkipReason, "первой версии") {
		t.Errorf("hysteria 1: %+v", o)
	}
	users := map[string]SrcUser{}
	for _, u := range data.Users {
		users[u.Name] = u
	}
	ann := users["ann"]
	if ann.Password != "hy-pass-1" || ann.UUID != uuidA || ann.SubID != "subAnn" {
		t.Errorf("ann (hysteria + tuic склеены): %+v", ann)
	}
	if !hasWarn(ann.Warnings, "разные пароли") {
		t.Errorf("нет предупреждения о разных паролях: %v", ann.Warnings)
	}
	if ben := users["ben"]; ben.Password != "hy-pass-2" {
		t.Errorf("ben: %+v", ben)
	}
}

func hasWarn(ws []string, sub string) bool {
	for _, w := range ws {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

func TestHysteria2ApplyKeepsLinkData(t *testing.T) {
	k := openKitsune(t)
	data, _ := Read3XUI(quicFixture(t))
	rep, err := Run(k, data, opts(true, false))
	if err != nil {
		t.Fatal(err)
	}
	if rep.InSum.Create != 2 || rep.InSum.Skip != 1 {
		t.Fatalf("подключения: %+v", rep.InSum)
	}
	var protocol, kind, js string
	var port int
	if err := k.QueryRow(`SELECT protocol, kind, port, settings FROM inbounds WHERE kind = 'hysteria2'`).Scan(&protocol, &kind, &port, &js); err != nil {
		t.Fatal(err)
	}
	if protocol != "hysteria" || port != 8443 {
		t.Errorf("protocol=%s port=%d", protocol, port)
	}
	if s := proto.ParseSettings(js); s.ObfsPassword != "obfs-secret" || s.SNI != "hy.example.com" || s.CertMode != "custom" {
		t.Errorf("сохранённые настройки: %+v", s)
	}
	var pass, uid string
	if err := k.QueryRow(`SELECT password, uuid FROM users WHERE name = 'ben'`).Scan(&pass, &uid); err != nil || pass != "hy-pass-2" {
		t.Errorf("пароль ben: %q %v", pass, err)
	}
	if err := k.QueryRow(`SELECT uuid FROM users WHERE name = 'ann'`).Scan(&uid); err != nil || uid != uuidA {
		t.Errorf("uuid ann: %q %v", uid, err)
	}
	raw := jsonOf(t, rep)
	for _, secret := range []string{"hy-pass-1", "hy-pass-2", "tuic-pass", "obfs-secret", uuidA} {
		if strings.Contains(raw, secret) {
			t.Errorf("в отчёте открытый секрет %q", secret)
		}
	}
}

func TestMasqueradeChecks(t *testing.T) {
	cases := []struct {
		name string
		in   m
		ok   bool
	}{
		{"proxy https", m{"type": "proxy", "url": "https://example.org/x"}, true},
		{"proxy localhost", m{"type": "proxy", "url": "http://127.0.0.1:8080"}, false},
		{"proxy private", m{"type": "proxy", "url": "https://10.0.0.5"}, false},
		{"proxy userinfo", m{"type": "proxy", "url": "https://a:b@example.org"}, false},
		{"proxy not url", m{"type": "proxy", "url": "ftp://example.org"}, false},
		{"string html", m{"type": "string", "content": "<h1>hi</h1>"}, true},
		{"string url-like", m{"type": "string", "content": " HTTP://169.254.169.254/"}, false},
		{"string huge", m{"type": "string", "content": strings.Repeat("a", maxMasqueradeBytes+1)}, false},
		{"file", m{"type": "file", "dir": "/etc"}, false},
	}
	for _, c := range cases {
		v, w := masqueradeOf(c.in)
		if (v != "") != c.ok || (!c.ok && w == "") {
			t.Errorf("%s: val=%q warn=%q", c.name, v, w)
		}
	}
}

func TestQUICTLSNames(t *testing.T) {
	for _, bad := range []string{"localhost", "10.1.2.3", "*.example.com", "bad name"} {
		var s proto.Settings
		w := quicTLS(m{"tlsSettings": m{"serverName": bad}}, &s)
		if s.SNI != "" || len(w) < 2 {
			t.Errorf("%q: sni=%q warns=%v", bad, s.SNI, w)
		}
	}
	var s proto.Settings
	_ = quicTLS(m{"tlsSettings": m{"serverName": "ok.example.com", "certificates": []m{{"certificateFile": "/a/../b", "keyFile": "/k"}}}}, &s)
	if s.SNI != "ok.example.com" || s.CertMode != "self" {
		t.Errorf("путь с .. не должен переноситься: %+v", s)
	}
}

func TestNewSchemaHysteriaAuth(t *testing.T) {
	d, p := newFile(t)
	mustExec(t, d, `CREATE TABLE inbounds (id INTEGER PRIMARY KEY, remark TEXT, enable NUMERIC, listen TEXT, port INT, protocol TEXT, settings TEXT, stream_settings TEXT, tag TEXT)`)
	mustExec(t, d, `CREATE TABLE clients (id INTEGER PRIMARY KEY, email TEXT, sub_id TEXT, uuid TEXT, password TEXT, auth TEXT, flow TEXT, limit_ip INT, total_gb INT, expiry_time INT, enable NUMERIC, comment TEXT)`)
	mustExec(t, d, `INSERT INTO inbounds VALUES (1, 'HY', 1, '', 8443, 'hysteria2', ?, '{}', 'in-8443')`, jsonOf(t, m{"clients": []m{{"email": "zed", "auth": "old"}}}))
	mustExec(t, d, `INSERT INTO clients (email, sub_id, uuid, password, auth, enable) VALUES ('zed', 'subZed', '', '', 'hy-new-auth', 1)`)
	data, err := Read3XUI(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Users) != 1 || data.Users[0].Password != "hy-new-auth" {
		t.Fatalf("%+v", data.Users)
	}
	if data.Inbounds[0].Kind != proto.Hysteria2 {
		t.Fatalf("%+v", data.Inbounds[0])
	}
}
