package importer

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"kitsune/internal/db"
	"kitsune/internal/proto"
)

type imrow struct {
	id       int
	remark   string
	port     int
	protocol string
	settings any
	stream   any
}

func imdb(t *testing.T, rows ...imrow) string {
	d, p := newFile(t)
	mustExec(t, d, `CREATE TABLE inbounds (id INTEGER PRIMARY KEY, remark TEXT, enable NUMERIC, listen TEXT, port INT, protocol TEXT, settings TEXT, stream_settings TEXT, tag TEXT)`)
	for _, r := range rows {
		s, st := "", ""
		switch v := r.settings.(type) {
		case string:
			s = v
		default:
			s = jsonOf(t, v)
		}
		switch v := r.stream.(type) {
		case nil:
			st = "{}"
		case string:
			st = v
		default:
			st = jsonOf(t, v)
		}
		mustExec(t, d, `INSERT INTO inbounds VALUES (?, ?, 1, '', ?, ?, ?, ?, ?)`, r.id, r.remark, r.port, r.protocol, s, st, fmt.Sprintf("in-%d", r.port))
	}
	return p
}

func hyStream(extra m) m {
	s := m{"network": "hysteria", "security": "tls", "tlsSettings": m{"serverName": "hy.example.com"}, "hysteriaSettings": m{"version": 2}}
	for k, v := range extra {
		s[k] = v
	}
	return s
}

// Hy2: разные места пароля клиента, разные формы версии.
func TestImportMoreHyPasswordsAndVersions(t *testing.T) {
	p := imdb(t,
		imrow{1, "A-auth", 8001, "hysteria", m{"version": 2, "clients": []m{{"auth": "pA", "email": "a1", "subId": "s1"}}}, hyStream(nil)},
		imrow{2, "B-password", 8002, "hysteria2", m{"clients": []m{{"password": "pB", "email": "b1", "subId": "s2"}}}, hyStream(nil)},
		imrow{3, "C-both", 8003, "hysteria", m{"version": 2, "clients": []m{{"auth": "pAuth", "password": "pPass", "email": "c1", "subId": "s3"}}}, hyStream(nil)},
		imrow{4, "D-ver-in-stream", 8004, "hysteria", m{"clients": []m{}}, hyStream(nil)},
		imrow{5, "E-ver-str", 8005, "hysteria", m{"version": "2", "clients": []m{}}, m{"network": "hysteria", "security": "tls"}},
		imrow{6, "F-v1", 8006, "hysteria", m{"version": 1, "clients": []m{{"auth": "x", "email": "v1user", "subId": "s6"}}}, m{"network": "hysteria", "security": "tls"}},
		imrow{7, "G-nover", 8007, "hysteria", m{"clients": []m{}}, m{"network": "hysteria", "security": "tls"}},
		imrow{8, "H-nontls", 8008, "hysteria", m{"version": 2, "clients": []m{}}, m{"network": "hysteria", "security": "none"}},
		imrow{9, "I-wrongnet", 8009, "hysteria", m{"version": 2, "clients": []m{}}, m{"network": "tcp", "security": "tls"}},
		imrow{10, "J-longauth", 8010, "hysteria", m{"version": 2, "clients": []m{{"auth": strings.Repeat("a", 129), "email": "long", "subId": "s10"}}}, hyStream(nil)},
		imrow{11, "K-spaceauth", 8011, "hysteria", m{"version": 2, "clients": []m{{"auth": "has space", "email": "sp", "subId": "s11"}}}, hyStream(nil)},
		imrow{12, "L-colonauth", 8012, "hysteria", m{"version": 2, "clients": []m{{"auth": "user:p@ss/w#rd?", "email": "col", "subId": "s12"}}}, hyStream(nil)},
	)
	data, err := Read3XUI(p)
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]SrcInbound{}
	for _, i := range data.Inbounds {
		in[i.Name] = i
	}
	for _, n := range []string{"A-auth", "B-password", "C-both", "D-ver-in-stream", "E-ver-str", "J-longauth", "K-spaceauth", "L-colonauth"} {
		if in[n].Kind != proto.Hysteria2 {
			t.Errorf("%s: kind=%q skip=%q", n, in[n].Kind, in[n].SkipReason)
		}
	}
	for _, n := range []string{"F-v1", "G-nover", "H-nontls", "I-wrongnet"} {
		if in[n].Kind != "" || in[n].SkipReason == "" {
			t.Errorf("%s должно быть пропущено с причиной: %+v", n, in[n])
		} else {
			t.Logf("%s -> %s", n, in[n].SkipReason)
		}
	}
	us := map[string]SrcUser{}
	for _, u := range data.Users {
		us[u.Name] = u
	}
	want := map[string]string{"a1": "pA", "b1": "pB", "c1": "pAuth", "col": "user:p@ss/w#rd?"}
	for n, pw := range want {
		if us[n].Password != pw {
			t.Errorf("%s: пароль %q, ждали %q", n, us[n].Password, pw)
		}
	}
	for _, n := range []string{"long", "sp"} {
		t.Logf("%s: пароль=%q предупреждения=%v", n, us[n].Password, us[n].Warnings)
		if us[n].Password != "" {
			t.Errorf("%s: недопустимый пароль перенесён", n)
		}
		if len(us[n].Warnings) == 0 {
			t.Errorf("%s: пароль не перенесён молча (нет предупреждения) – ссылка пользователя изменится без объяснения", n)
		}
	}
	if u, ok := us["v1user"]; ok {
		t.Logf("v1user (из пропущенного Hysteria1) попал в пользователи: %+v", u)
	}
}

// Hy2: параметры.
func TestImportMoreHyParams(t *testing.T) {
	cases := []struct {
		name  string
		extra m
		check func(s proto.Settings, w []string) string
	}{
		{"obfs-ok", m{"finalmask": m{"udp": []m{{"type": "salamander", "settings": m{"password": "ob-1"}}}}}, func(s proto.Settings, w []string) string {
			if s.ObfsPassword != "ob-1" {
				return "obfs " + s.ObfsPassword
			}
			return ""
		}},
		{"obfs-upper", m{"finalmask": m{"udp": []m{{"type": "Salamander", "settings": m{"password": "ob-2"}}}}}, func(s proto.Settings, w []string) string {
			if s.ObfsPassword != "ob-2" {
				return "obfs " + s.ObfsPassword
			}
			return ""
		}},
		{"obfs-other-then-sala", m{"finalmask": m{"udp": []m{{"type": "xdns"}, {"type": "salamander", "settings": m{"password": "ob-3"}}}}}, func(s proto.Settings, w []string) string {
			if s.ObfsPassword != "ob-3" || !hasWarn(w, "кроме salamander") {
				return fmt.Sprintf("obfs=%q w=%v", s.ObfsPassword, w)
			}
			return ""
		}},
		{"obfs-badpw", m{"finalmask": m{"udp": []m{{"type": "salamander", "settings": m{"password": "bad pass\n"}}}}}, func(s proto.Settings, w []string) string {
			if s.ObfsPassword != "" || !hasWarn(w, "обфускации") {
				return fmt.Sprintf("obfs=%q w=%v", s.ObfsPassword, w)
			}
			return ""
		}},
		{"obfs-nopw", m{"finalmask": m{"udp": []m{{"type": "salamander"}}}}, func(s proto.Settings, w []string) string {
			t.Logf("obfs-nopw: obfs=%q w=%v", s.ObfsPassword, w)
			return ""
		}},
		{"obfs-udp-notarray", m{"finalmask": m{"udp": "x"}}, func(s proto.Settings, w []string) string { return "" }},
		{"obfs-udp-items-junk", m{"finalmask": m{"udp": []any{1, "a", nil, []any{}}}}, func(s proto.Settings, w []string) string { return "" }},
		{"limits-ok", m{"finalmask": m{"quicParams": m{"brutalUp": "100 mbps", "brutalDown": "50"}}}, func(s proto.Settings, w []string) string {
			if s.UpMbps != "100" || s.DownMbps != "50" {
				return fmt.Sprintf("%q %q", s.UpMbps, s.DownMbps)
			}
			return ""
		}},
		{"limits-num", m{"finalmask": m{"quicParams": m{"brutalUp": 30, "brutalDown": 12.7}}}, func(s proto.Settings, w []string) string {
			t.Logf("limits-num: %q %q", s.UpMbps, s.DownMbps)
			return ""
		}},
		{"limits-units", m{"finalmask": m{"quicParams": m{"brutalUp": "1 gbps", "brutalDown": "100 kbps"}}}, func(s proto.Settings, w []string) string {
			t.Logf("limits-units: up=%q down=%q w=%v", s.UpMbps, s.DownMbps, w)
			return ""
		}},
		{"limits-junk", m{"finalmask": m{"quicParams": m{"brutalUp": "-5", "brutalDown": "1e9"}}}, func(s proto.Settings, w []string) string {
			if s.UpMbps != "" || s.DownMbps != "" {
				return fmt.Sprintf("%q %q", s.UpMbps, s.DownMbps)
			}
			return ""
		}},
		{"limits-huge", m{"finalmask": m{"quicParams": m{"brutalUp": "999999", "brutalDown": "100001"}}}, func(s proto.Settings, w []string) string {
			t.Logf("limits-huge: up=%q down=%q", s.UpMbps, s.DownMbps)
			return ""
		}},
		{"idle-0", m{"hysteriaSettings": m{"version": 2, "udpIdleTimeout": 0}}, func(s proto.Settings, w []string) string {
			if s.UDPIdleTimeout != "" {
				return s.UDPIdleTimeout
			}
			return ""
		}},
		{"idle-big", m{"hysteriaSettings": m{"version": 2, "udpIdleTimeout": 86401}}, func(s proto.Settings, w []string) string {
			if s.UDPIdleTimeout != "" {
				return s.UDPIdleTimeout
			}
			return ""
		}},
		{"idle-ok", m{"hysteriaSettings": m{"version": 2, "udpIdleTimeout": 90}}, func(s proto.Settings, w []string) string {
			if s.UDPIdleTimeout != "90" {
				return s.UDPIdleTimeout
			}
			return ""
		}},
		{"masq-proxy", m{"hysteriaSettings": m{"version": 2, "masquerade": m{"type": "proxy", "url": "https://news.example.org/path?q=1"}}}, func(s proto.Settings, w []string) string {
			if s.Masquerade != "https://news.example.org/path?q=1" {
				return s.Masquerade
			}
			return ""
		}},
		{"masq-local", m{"hysteriaSettings": m{"version": 2, "masquerade": m{"type": "proxy", "url": "http://127.0.0.1:8080"}}}, func(s proto.Settings, w []string) string {
			if s.Masquerade != "" || !hasWarn(w, "маскировка") {
				return fmt.Sprintf("%q %v", s.Masquerade, w)
			}
			return ""
		}},
		{"masq-userinfo", m{"hysteriaSettings": m{"version": 2, "masquerade": m{"type": "proxy", "url": "https://u:p@example.org"}}}, func(s proto.Settings, w []string) string {
			if s.Masquerade != "" {
				return s.Masquerade
			}
			return ""
		}},
		{"masq-file", m{"hysteriaSettings": m{"version": 2, "masquerade": m{"type": "file", "dir": "/var/www"}}}, func(s proto.Settings, w []string) string {
			if s.Masquerade != "" || !hasWarn(w, "не переносится") {
				return fmt.Sprintf("%q %v", s.Masquerade, w)
			}
			return ""
		}},
		{"masq-string", m{"hysteriaSettings": m{"version": 2, "masquerade": m{"type": "string", "content": "<html>hi</html>"}}}, func(s proto.Settings, w []string) string {
			if s.Masquerade != "<html>hi</html>" {
				return s.Masquerade
			}
			return ""
		}},
		{"masq-string-url", m{"hysteriaSettings": m{"version": 2, "masquerade": m{"type": "string", "content": "https://x.org"}}}, func(s proto.Settings, w []string) string {
			if s.Masquerade != "" {
				return s.Masquerade
			}
			return ""
		}},
		{"masq-big", m{"hysteriaSettings": m{"version": 2, "masquerade": m{"type": "string", "content": strings.Repeat("a", 9000)}}}, func(s proto.Settings, w []string) string {
			if s.Masquerade != "" {
				return "перенесено"
			}
			return ""
		}},
		{"masq-notobject", m{"hysteriaSettings": m{"version": 2, "masquerade": "x"}}, func(s proto.Settings, w []string) string { return "" }},
		{"sni-wild", m{"tlsSettings": m{"serverName": "*.example.com"}}, func(s proto.Settings, w []string) string {
			if s.SNI != "" {
				return s.SNI
			}
			return ""
		}},
		{"sni-ip", m{"tlsSettings": m{"serverName": "203.0.113.5"}}, func(s proto.Settings, w []string) string {
			if s.SNI != "203.0.113.5" {
				return "sni=" + s.SNI
			}
			return ""
		}},
		{"sni-local", m{"tlsSettings": m{"serverName": "localhost"}}, func(s proto.Settings, w []string) string {
			if s.SNI != "" {
				return s.SNI
			}
			return ""
		}},
		{"cert-ok", m{"tlsSettings": m{"serverName": "hy.example.com", "certificates": []m{{"certificateFile": "/etc/ssl/a.crt", "keyFile": "/etc/ssl/a.key"}}}}, func(s proto.Settings, w []string) string {
			if s.CertMode != "custom" || s.CertFile != "/etc/ssl/a.crt" {
				return fmt.Sprintf("%+v", s)
			}
			return ""
		}},
		{"cert-relative", m{"tlsSettings": m{"serverName": "hy.example.com", "certificates": []m{{"certificateFile": "a.crt", "keyFile": "a.key"}}}}, func(s proto.Settings, w []string) string {
			if s.CertMode != "self" {
				return s.CertMode
			}
			return ""
		}},
		{"cert-dotdot", m{"tlsSettings": m{"serverName": "hy.example.com", "certificates": []m{{"certificateFile": "/etc/../root/a.crt", "keyFile": "/etc/ssl/a.key"}}}}, func(s proto.Settings, w []string) string {
			if s.CertMode != "self" {
				return s.CertMode
			}
			return ""
		}},
		{"cert-inline", m{"tlsSettings": m{"serverName": "hy.example.com", "certificates": []m{{"certificate": []string{"-----BEGIN CERTIFICATE-----", "x"}, "key": []string{"-----BEGIN PRIVATE KEY-----", "y"}}}}}, func(s proto.Settings, w []string) string {
			t.Logf("cert-inline: mode=%s w=%v", s.CertMode, w)
			if s.CertMode != "self" {
				return s.CertMode
			}
			return ""
		}},
		{"cert-sensitive-path", m{"tlsSettings": m{"serverName": "hy.example.com", "certificates": []m{{"certificateFile": "/etc/shadow", "keyFile": "/root/.ssh/id_rsa"}}}}, func(s proto.Settings, w []string) string {
			t.Logf("cert-sensitive-path: mode=%s cert=%s key=%s", s.CertMode, s.CertFile, s.KeyFile)
			return ""
		}},
		{"stream-junk-types", m{"hysteriaSettings": "x", "finalmask": []any{1}, "tlsSettings": 5}, func(s proto.Settings, w []string) string { return "" }},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			st := hyStream(c.extra)
			if _, ok := c.extra["hysteriaSettings"]; !ok {
				st["hysteriaSettings"] = m{"version": 2}
			}
			p := imdb(t, imrow{1, "H", 8443, "hysteria", m{"version": 2, "clients": []m{}}, st})
			data, err := Read3XUI(p)
			if err != nil {
				t.Fatal(err)
			}
			in := data.Inbounds[0]
			if in.Kind != proto.Hysteria2 {
				t.Fatalf("не Hysteria2: %+v", in)
			}
			if msg := c.check(in.Settings, in.Warnings); msg != "" {
				t.Error(msg)
			}
		})
	}
}

func TestImportMoreTUIC(t *testing.T) {
	type tc struct {
		name string
		st   m
		chk  func(s proto.Settings) string
	}
	cases := []tc{
		{"all", m{"congestion_control": "new_reno", "udp_relay_mode": "native", "zero_rtt_handshake": true, "heartbeat": "10s", "auth_timeout": "3s"}, func(s proto.Settings) string {
			if s.Congestion != "new_reno" || s.UDPRelayMode != "native" || s.ZeroRTT != "true" || s.Heartbeat != "10s" || s.AuthTimeout != "3s" {
				return fmt.Sprintf("%+v", s)
			}
			return ""
		}},
		{"bad-values", m{"congestion_control": "BBR", "udp_relay_mode": "x", "zero_rtt_handshake": "maybe", "heartbeat": "10", "auth_timeout": "1h30m"}, func(s proto.Settings) string {
			t.Logf("bad-values: %+v", s)
			return ""
		}},
		{"zero-rtt-str", m{"zero_rtt_handshake": "true"}, func(s proto.Settings) string {
			if s.ZeroRTT != "true" {
				return "zero:" + s.ZeroRTT
			}
			return ""
		}},
		{"zero-rtt-false", m{"zero_rtt_handshake": false}, func(s proto.Settings) string {
			if s.ZeroRTT == "true" {
				return "zero:" + s.ZeroRTT
			}
			return ""
		}},
		{"heartbeat-ms", m{"heartbeat": "1500ms", "auth_timeout": "99999s"}, func(s proto.Settings) string {
			t.Logf("heartbeat-ms: hb=%q at=%q", s.Heartbeat, s.AuthTimeout)
			return ""
		}},
		{"heartbeat-0s", m{"heartbeat": "0s"}, func(s proto.Settings) string {
			t.Logf("heartbeat-0s: hb=%q", s.Heartbeat)
			return ""
		}},
		{"heartbeat-injection", m{"heartbeat": "1s\",\"x\":\"y"}, func(s proto.Settings) string {
			if s.Heartbeat != "" {
				return s.Heartbeat
			}
			return ""
		}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			st := c.st
			st["users"] = []m{{"uuid": uuidA, "password": "tp", "name": "tu"}}
			p := imdb(t, imrow{1, "T", 8444, "tuic", st, m{"network": "tcp"}})
			data, err := Read3XUI(p)
			if err != nil {
				t.Fatal(err)
			}
			in := data.Inbounds[0]
			if in.Kind != proto.TUIC {
				t.Fatalf("%+v", in)
			}
			if msg := c.chk(in.Settings); msg != "" {
				t.Error(msg)
			}
		})
	}
}

// Клиенты TUIC: clients, users, имя из name/email, uuid из uuid/id, без имени, без uuid.
func TestImportMoreTUICClients(t *testing.T) {
	p := imdb(t,
		imrow{1, "T1", 8444, "tuic", m{"users": []m{{"uuid": uuidA, "password": "p1", "name": "alice", "subId": "sa"}, {"id": uuidB, "password": "p2", "email": "bob", "subId": "sb"}}}, nil},
		imrow{2, "T2", 8445, "tuic", m{"clients": []m{{"id": "cc111111-2222-4333-8444-555555555555", "password": "p3", "email": "carol", "subId": "sc"}}, "users": []m{{"uuid": uuidA, "name": "ignored"}}}, nil},
		imrow{3, "T3", 8446, "tuic", m{"users": []any{m{"password": "p4", "name": "nouuid", "subId": "sn"}, m{"uuid": uuidB}, "junk", nil, 5}}, nil},
		imrow{4, "T4", 8447, "tuic", m{"users": "oops"}, nil},
	)
	data, err := Read3XUI(p)
	if err != nil {
		t.Fatal(err)
	}
	us := map[string]SrcUser{}
	for _, u := range data.Users {
		us[u.Name] = u
		t.Logf("user %q uuid=%s pw=%q w=%v", u.Name, u.UUID, u.Password, u.Warnings)
	}
	if us["alice"].UUID != uuidA || us["alice"].Password != "p1" {
		t.Errorf("alice %+v", us["alice"])
	}
	if us["bob"].UUID != uuidB || us["bob"].Password != "p2" {
		t.Errorf("bob %+v", us["bob"])
	}
	if _, ok := us["ignored"]; ok {
		t.Error("users при наличии clients не используется")
	}
	if us["carol"].Password != "p3" {
		t.Errorf("carol %+v", us["carol"])
	}
	if _, ok := us["nouuid"]; !ok {
		t.Error("клиент TUIC без uuid потерян")
	}
}

// Ссылка после импорта: пароль, порт, SNI, obfs; TUIC: uuid, пароль.
func TestImportMoreLinksAfterImport(t *testing.T) {
	p := imdb(t,
		imrow{1, "HY", 8443, "hysteria", m{"version": 2, "clients": []m{{"auth": "hy:p@ss/w#rd", "email": "ann-hy", "subId": "subAnn"}}},
			hyStream(m{"tlsSettings": m{"serverName": "hy.example.com", "certificates": []m{{"certificateFile": "/etc/ssl/hy.crt", "keyFile": "/etc/ssl/hy.key"}}},
				"finalmask": m{"udp": []m{{"type": "salamander", "settings": m{"password": "ob~secret"}}}}})},
		imrow{2, "TU", 8444, "tuic", m{"congestion_control": "cubic", "udp_relay_mode": "quic", "users": []m{{"uuid": uuidA, "password": "hy:p@ss/w#rd", "name": "ann-tuic", "subId": "subAnn"}}},
			m{"tlsSettings": m{"serverName": "tu.example.com", "certificates": []m{{"certificateFile": "/etc/ssl/tu.crt", "keyFile": "/etc/ssl/tu.key"}}}}},
	)
	k := openKitsune(t)
	data, err := Read3XUI(p)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Run(k, data, opts(true, false))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("users %+v inbounds %+v warnings=%v", rep.UserSum, rep.InSum, rep.Warnings)
	ins, _ := db.GetInbounds()
	us, _ := db.GetUsers()
	if len(us) != 1 || len(ins) != 2 {
		t.Fatalf("users=%d inbounds=%d", len(us), len(ins))
	}
	for _, in := range ins {
		pr, err := proto.NewProfile(in, us[0], proto.Env{Host: "203.0.113.9"})
		if err != nil {
			t.Fatal(err)
		}
		link := pr.URI()
		u, err := url.Parse(link)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		t.Logf("%s -> %s", in.Kind, link)
		switch in.Kind {
		case "hysteria2":
			pw, _ := url.PathUnescape(u.User.String())
			if pw != "hy:p@ss/w#rd" && u.User.Username() != "hy" {
				t.Errorf("пароль в ссылке: %q", u.User.String())
			}
			if u.Port() != "8443" || u.Query().Get("sni") != "hy.example.com" || u.Query().Get("obfs") != "salamander" || u.Query().Get("obfs-password") != "ob~secret" {
				t.Errorf("параметры ссылки: %s", link)
			}
			if u.Query().Get("insecure") != "" {
				t.Errorf("insecure в ссылке при своём сертификате: %s", link)
			}
		case "tuic":
			if !strings.HasPrefix(link, "tuic://"+uuidA+":hy%3Ap%40ss%2Fw%23rd@203.0.113.9:8444") || u.Query().Get("sni") != "tu.example.com" ||
				u.Query().Get("congestion_control") != "cubic" || u.Query().Get("udp_relay_mode") != "quic" {
				t.Errorf("ссылка tuic: %s", link)
			}
		}
	}
	// пароль и uuid пользователя
	if us[0].SubID != "subAnn" || us[0].UUID != uuidA {
		t.Errorf("user: %+v", us[0])
	}
	if rep.UserSum.Create == 1 {
		t.Logf("отчёт: %+v", rep.Users)
	}
	t.Logf("пароль пользователя после импорта: %q (ждали пароль Hysteria 2 – первый)", us[0].Password)
}

// Разные пароли у одного человека.
func TestImportMoreDifferentPasswords(t *testing.T) {
	p := imdb(t,
		imrow{1, "HY", 8443, "hysteria", m{"version": 2, "clients": []m{{"auth": "pass-hy", "email": "ann@hy", "subId": "S"}}}, hyStream(nil)},
		imrow{2, "TR", 8444, "trojan", m{"clients": []m{{"password": "pass-tr", "email": "ann@tr", "subId": "S"}}}, m{"network": "tcp", "security": "tls", "tlsSettings": m{"serverName": "t.example.com"}}},
		imrow{3, "TU", 8445, "tuic", m{"users": []m{{"uuid": uuidA, "password": "pass-tu", "name": "ann@tu", "subId": "S"}}}, nil},
	)
	data, err := Read3XUI(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Users) != 1 {
		t.Fatalf("users=%d", len(data.Users))
	}
	u := data.Users[0]
	t.Logf("%+v", u)
	if u.Password != "pass-hy" || !hasWarn(u.Warnings, "разные пароли") {
		t.Errorf("пароль/предупреждение: %q %v", u.Password, u.Warnings)
	}
	k := openKitsune(t)
	rep, err := Run(k, data, opts(false, false))
	if err != nil {
		t.Fatal(err)
	}
	js := jsonOf(t, rep)
	if !strings.Contains(js, "разные пароли") {
		t.Error("предупреждение о разных паролях не попало в отчёт")
	}
	for _, s := range []string{"pass-hy", "pass-tr", "pass-tu"} {
		if strings.Contains(js, s) {
			t.Errorf("секрет %s в отчёте", s)
		}
	}
	// три одинаковых пароля – без предупреждения
	p2 := imdb(t,
		imrow{1, "HY", 8443, "hysteria", m{"version": 2, "clients": []m{{"auth": "same", "email": "bob@hy", "subId": "B"}}}, hyStream(nil)},
		imrow{2, "TR", 8444, "trojan", m{"clients": []m{{"password": "same", "email": "bob@tr", "subId": "B"}}}, m{"network": "tcp", "security": "tls"}},
	)
	d2, _ := Read3XUI(p2)
	if len(d2.Users) != 1 || hasWarn(d2.Users[0].Warnings, "разные пароли") {
		t.Errorf("ложное предупреждение: %+v", d2.Users)
	}
}

// config.json Xray.
func TestImportMoreXrayConfig(t *testing.T) {
	dir := t.TempDir()
	w := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := `{"inbounds":[
	 {"tag":"api","listen":"127.0.0.1","port":62789,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1"}},
	 {"tag":"lo","listen":"127.0.0.1","port":2000,"protocol":"vless","settings":{"clients":[],"decryption":"none"}},
	 {"tag":"lo6","listen":"::1","port":2001,"protocol":"vless","settings":{"clients":[],"decryption":"none"}},
	 {"tag":"lo-name","listen":"localhost","port":2002,"protocol":"vless","settings":{"clients":[],"decryption":"none"}},
	 {"tag":"pub","listen":"0.0.0.0","port":443,"protocol":"vless","settings":{"clients":[{"id":"` + uuidA + `","email":"u1"}],"decryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"dest":"example.com:443","serverNames":["example.com"],"privateKey":"x","shortIds":["ab"]}}},
	 {"tag":"nolisten","port":8443,"protocol":"trojan","settings":{"clients":[{"password":"tp","email":"u2"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"t.example.com"}}},
	 {"tag":"unix","listen":"/dev/shm/x.sock,0666","port":0,"protocol":"vless","settings":{"clients":[]}},
	 {"tag":"strport","listen":"","port":"8444","protocol":"trojan","settings":{"clients":[]}},
	 {"tag":"range","port":"1000-2000","protocol":"vless","settings":{"clients":[]}},
	 {"tag":"hy","port":8445,"protocol":"hysteria","settings":{"version":2,"clients":[{"auth":"hyp","email":"u3"}]},"streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"hy.example.com"},"hysteriaSettings":{"version":2}}}
	]}`
	d, err := ReadXrayConfig(w("good.json", good))
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range d.Inbounds {
		t.Logf("inbound %-8s port=%-5d kind=%-12s skip=%q", i.Name, i.Port, i.Kind, i.SkipReason)
	}
	byName := map[string]SrcInbound{}
	for _, i := range d.Inbounds {
		byName[i.Name] = i
	}
	for _, n := range []string{"api", "lo", "lo6", "lo-name", "unix"} {
		if byName[n].Kind != "" || byName[n].SkipReason == "" {
			t.Errorf("%s должно быть пропущено: %+v", n, byName[n])
		}
	}
	for _, n := range []string{"pub", "hy"} {
		if byName[n].Kind == "" {
			t.Errorf("%s не перенесено: %+v", n, byName[n])
		}
	}
	if len(d.Users) != 3 {
		t.Errorf("users=%d", len(d.Users))
	}

	// комментарии
	for name, body := range map[string]string{
		"c-line.json":   "{\n // комментарий\n \"inbounds\":[{\"tag\":\"a\",\"port\":1000,\"protocol\":\"vless\"}]}",
		"c-block.json":  "{ /* x */ \"inbounds\":[{\"tag\":\"a\",\"port\":1000,\"protocol\":\"vless\"}]}",
		"bom.json":      "\xef\xbb\xbf{\"inbounds\":[{\"tag\":\"a\",\"port\":1000,\"protocol\":\"vless\"}]}",
		"trailing.json": "{\"inbounds\":[{\"tag\":\"a\",\"port\":1000,\"protocol\":\"vless\"},]}",
		"empty.json":    "",
		"spaces.json":   "   \n ",
		"null.json":     "null",
		"arr.json":      "[]",
		"noinb.json":    "{}",
		"inbnull.json":  `{"inbounds":null}`,
		"inbobj.json":   `{"inbounds":{}}`,
		"inbjunk.json":  `{"inbounds":[1,"a",null,[],{}]}`,
		"binary.json":   "\x00\x01\x02\xff\xfe",
		"deep.json":     strings.Repeat("[", 100000),
		"dupkey.json":   `{"inbounds":[{"tag":"a","tag":"b","port":1000,"protocol":"vless"}]}`,
		"portbig.json":  `{"inbounds":[{"tag":"a","port":1e400,"protocol":"vless"}]}`,
		"portneg.json":  `{"inbounds":[{"tag":"a","port":-1,"protocol":"vless"}]}`,
		"notag.json":    `{"inbounds":[{"port":1000,"protocol":"vless"},{"port":1001,"protocol":"vless"}]}`,
		"sametag.json":  `{"inbounds":[{"tag":"a","port":1000,"protocol":"vless"},{"tag":"a","port":1001,"protocol":"vless"}]}`,
		"sameport.json": `{"inbounds":[{"tag":"a","port":1000,"protocol":"vless"},{"tag":"b","port":1000,"protocol":"vless"}]}`,
		"xss.json":      `{"inbounds":[{"tag":"<script>alert(1)</script>","port":1000,"protocol":"vless"}]}`,
	} {
		d, err := ReadXrayConfig(w(name, body))
		if err != nil {
			t.Logf("%-14s -> ошибка: %v", name, err)
			continue
		}
		var s []string
		for _, i := range d.Inbounds {
			s = append(s, fmt.Sprintf("%s:%d:%s:%q", i.Name, i.Port, i.Kind, i.SkipReason))
		}
		t.Logf("%-14s -> ok %v", name, s)
	}

	// размер
	pad := func(n int) string {
		return `{"inbounds":[{"tag":"a","port":1000,"protocol":"vless"}],"pad":"` + strings.Repeat("a", n)
	}
	body := pad(MaxConfigSize-len(pad(0))-2) + `"}`
	if len(body) != MaxConfigSize {
		t.Fatalf("len=%d", len(body))
	}
	if _, err := ReadXrayConfig(w("exact8.json", body)); err != nil {
		t.Errorf("ровно 8 МБ: %v", err)
	}
	if _, err := ReadXrayConfig(w("over8.json", body+" ")); err == nil {
		t.Error("8 МБ + 1 принят")
	} else {
		t.Logf("8 МБ+1: %v", err)
	}
	// не файл
	if _, err := ReadXrayConfig(dir); err == nil {
		t.Error("каталог принят")
	}
	if _, err := ReadXrayConfig(filepath.Join(dir, "nope.json")); err == nil {
		t.Error("нет файла принят")
	}
	if err := os.Symlink(filepath.Join(dir, "good.json"), filepath.Join(dir, "link.json")); err == nil {
		if _, err := ReadXrayConfig(filepath.Join(dir, "link.json")); err != nil {
			t.Logf("симлинк на файл: %v", err)
		} else {
			t.Log("симлинк на файл читается (ок)")
		}
	}
	os.Chmod(w("noaccess.json", good), 0)
	if _, err := ReadXrayConfig(filepath.Join(dir, "noaccess.json")); err == nil {
		t.Log("chmod 000 читается (root?)")
	} else {
		t.Logf("chmod 000: %v", err)
	}
	// много подключений
	var sb strings.Builder
	sb.WriteString(`{"inbounds":[`)
	for i := 0; i < MaxInbounds+1; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"tag":"t%d","port":%d,"protocol":"vless"}`, i, 1000+i)
	}
	sb.WriteString("]}")
	if _, err := ReadXrayConfig(w("many.json", sb.String())); err == nil {
		t.Error("больше MaxInbounds принято")
	}
}

// Источник xray / marzban+config через Run: пустой источник, повтор.
func TestImportMoreXrayRun(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	os.WriteFile(p, []byte(`{"inbounds":[{"tag":"pub","port":18443,"protocol":"vless","settings":{"clients":[{"id":"`+uuidA+`","email":"u1"}],"decryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"dest":"example.com:443","serverNames":["example.com"],"privateKey":"x","shortIds":["ab"]}}}]}`), 0o600)
	k := openKitsune(t)
	d, err := ReadXrayConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		rep, err := Run(k, d, opts(true, false))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("прогон %d: users %+v inbounds %+v", i, rep.UserSum, rep.InSum)
	}
	if n := count(t, k, "inbounds"); n != 1 {
		t.Errorf("подключений %d после повторов", n)
	}
	// пустой
	empty := &Data{Source: SourceXray}
	rep, err := Run(k, empty, opts(true, false))
	t.Logf("пустой источник: %+v err=%v", rep != nil, err)
}

// Marzban API: логин, права, страницы, TLS.
func TestImportMoreAPIPaging(t *testing.T) {
	for _, n := range []int{0, 1, 99, 100, 101, 199, 200, 201, 1000} {
		srv := fakeMarzban(t, n, 200, `{"inbounds":[]}`)
		d, err := ReadMarzbanAPI(context.Background(), srv.URL, APIAuth{Token: apiToken})
		srv.Close()
		if err != nil {
			t.Errorf("n=%d: %v", n, err)
			continue
		}
		if len(d.Users) != n {
			t.Errorf("n=%d: получено %d", n, len(d.Users))
		}
	}
}

// Сервер отдаёт страницы короче запрошенной (лимит ниже 100): в примечании должно быть «прочитано N из M».
func TestImportMoreAPICappedPages(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		var off, lim int
		fmt.Sscan(r.URL.Query().Get("offset"), &off)
		fmt.Sscan(r.URL.Query().Get("limit"), &lim)
		if lim > 50 {
			lim = 50
		}
		s := `{"total":300,"users":[`
		for i := off; i < off+lim && i < 300; i++ {
			if i > off {
				s += ","
			}
			s += fmt.Sprintf(`{"username":"u%d"}`, i)
		}
		w.Write([]byte(s + "]}"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	d, err := ReadMarzbanAPI(context.Background(), srv.URL, APIAuth{Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("total=300, сервер отдаёт по 50, прочитано %d; примечания: %v", len(d.Users), d.Notes)
	if len(d.Users) != 300 {
		warned := false
		for _, n := range d.Notes {
			if strings.Contains(n, "не все") || strings.Contains(n, "меньше") || strings.Contains(n, "не полностью") {
				warned = true
			}
		}
		if !warned {
			t.Errorf("прочитано %d из 300 и об этом нет предупреждения", len(d.Users))
		}
	}
}

// Сервер игнорирует offset: те же 100 пользователей по кругу.
func TestImportMoreAPIIgnoresOffset(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		s := `{"total":100000,"users":[`
		for i := 0; i < 100; i++ {
			if i > 0 {
				s += ","
			}
			s += fmt.Sprintf(`{"username":"u%d"}`, i)
		}
		w.Write([]byte(s + "]}"))
	}))
	defer srv.Close()
	start := time.Now()
	d, err := ReadMarzbanAPI(context.Background(), srv.URL, APIAuth{Token: "t"})
	t.Logf("offset игнорируется: users=%d err=%v запросов=%d за %v", func() int {
		if d == nil {
			return -1
		}
		return len(d.Users)
	}(), err, hits, time.Since(start))
}

// Версия TLS и проверка сертификата. Server: только TLS 1.1 / 1.2.
func TestImportMoreTLSVersions(t *testing.T) {
	t.Setenv("GODEBUG", "tls10server=1")
	for _, tc := range []struct {
		name     string
		max      uint16
		min      uint16
		wantFail bool
	}{
		{"tls1.1", tls.VersionTLS11, tls.VersionTLS10, true},
		{"tls1.2", tls.VersionTLS12, tls.VersionTLS12, false},
		{"tls1.3", tls.VersionTLS13, tls.VersionTLS13, false},
	} {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"users":[{"username":"x"}],"total":1}`))
		}))
		srv.TLS = &tls.Config{MinVersion: tc.min, MaxVersion: tc.max}
		srv.StartTLS()
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		apiTransportHook = func(tr *http.Transport) { tr.TLSClientConfig.RootCAs = pool } // MinVersion остаётся прежний
		_, err := ReadMarzbanAPI(context.Background(), srv.URL, APIAuth{Token: "t"})
		apiTransportHook = nil
		srv.Close()
		if (err != nil) != tc.wantFail {
			t.Errorf("%s: err=%v wantFail=%v", tc.name, err, tc.wantFail)
		}
		t.Logf("%s: %v", tc.name, err)
	}
}

// Сертификат на другое имя.
func TestImportMoreTLSWrongName(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"users":[],"total":0}`)) }))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	apiTransportHook = func(tr *http.Transport) { tr.TLSClientConfig.RootCAs = pool }
	defer func() { apiTransportHook = nil }()
	// httptest-сертификат выдан на 127.0.0.1 и example.com: localhost – другое имя
	u := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	_, err := ReadMarzbanAPI(context.Background(), u, APIAuth{Token: "t"})
	t.Logf("имя не совпадает: %v", err)
	if err == nil || !strings.Contains(err.Error(), "сертификат") {
		t.Errorf("ждали ошибку сертификата, получили %v", err)
	}
}

// Ошибки не содержат ни токена, ни пароля, ни адреса.
func TestImportMoreAPIErrorsNoSecrets(t *testing.T) {
	secrets := []string{"tok-SECRET-9", "pw-SECRET-9", "usr-SECRET-9"}
	handlers := map[string]http.HandlerFunc{
		"echo-token-body": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "bad "+r.Header.Get("Authorization")+" "+r.URL.RawQuery, 500)
		},
		"login-echo": func(w http.ResponseWriter, r *http.Request) {
			r.ParseForm()
			http.Error(w, r.PostForm.Get("password"), 401)
		},
		"json-with-token": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"access_token":"` + secrets[0] + ` bad"}`))
		},
		"redirect-with-secret": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://evil.example/?t="+secrets[0], 302)
		},
	}
	for name, h := range handlers {
		srv := httptest.NewServer(h)
		for _, a := range []APIAuth{{Token: secrets[0]}, {Username: secrets[2], Password: secrets[1]}} {
			_, err := ReadMarzbanAPI(context.Background(), srv.URL, a)
			if err == nil {
				t.Errorf("%s: нет ошибки", name)
				continue
			}
			for _, s := range secrets {
				if strings.Contains(err.Error(), s) {
					t.Errorf("%s: секрет %s в ошибке: %v", name, s, err)
				}
			}
			if strings.Contains(err.Error(), srv.URL) || strings.Contains(err.Error(), "127.0.0.1") {
				t.Errorf("%s: адрес в ошибке: %v", name, err)
			}
		}
		srv.Close()
	}
}

// Заголовки запросов: токен только в Authorization, пароль только в теле login.
func TestImportMoreAPIRequestShape(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, fmt.Sprintf("%s %s?%s ct=%s auth=%v cookie=%v", r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Content-Type"), r.Header.Get("Authorization") != "", r.Header.Get("Cookie") != ""))
		switch r.URL.Path {
		case "/api/admin/token":
			r.ParseForm()
			if r.URL.RawQuery != "" {
				t.Error("секрет в query логина")
			}
			w.Write([]byte(`{"access_token":"abc.def.ghi"}`))
		default:
			if strings.Contains(r.URL.RawQuery, "abc.def") || strings.Contains(r.URL.RawQuery, "pw") {
				t.Error("секрет в query")
			}
			w.Write([]byte(`{"users":[],"total":0}`))
		}
	}))
	defer srv.Close()
	if _, err := ReadMarzbanAPI(context.Background(), srv.URL, APIAuth{Username: "root", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	for _, s := range seen {
		t.Log(s)
	}
}

// Параллельные и повторные вызовы не оставляют горутин/файлов.
func TestImportMoreAPINoFilesLeft(t *testing.T) {
	k := openKitsune(t)
	srv := fakeMarzban(t, 5, 200, `{"inbounds":[]}`)
	defer srv.Close()
	for i := 0; i < 3; i++ {
		d, err := ReadMarzbanAPI(context.Background(), srv.URL, APIAuth{Token: apiToken})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Run(k, d, opts(true, i == 2)); err != nil {
			t.Fatal(err)
		}
	}
	ents, _ := os.ReadDir(".")
	for _, e := range ents {
		t.Log("файл в каталоге данных:", e.Name())
	}
}

// Отчёт о пользователе, у которого пароль Hy2 не перенесён (длинный, пробелы).
func TestImportMoreReportDroppedPassword(t *testing.T) {
	p := imdb(t, imrow{1, "HY", 8443, "hysteria", m{"version": 2, "clients": []m{{"auth": "has space", "email": "sp", "subId": "s11"}, {"auth": "ok", "email": "okuser", "subId": "s12"}}}, hyStream(nil)})
	k := openKitsune(t)
	data, _ := Read3XUI(p)
	rep, err := Run(k, data, opts(false, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range rep.Users {
		t.Logf("%s [%s] details=%q reason=%q", it.Name, it.Action, it.Details, it.Reason)
	}
	t.Logf("warnings=%v notes=%v", rep.Warnings, rep.Notes)
}

// Типичный config.json Marzban: Reality с настоящим ключом, WS-подключения, Shadowsocks, служебный API.
func TestImportMoreMarzbanTypicalConfig(t *testing.T) {
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	priv := base64.RawURLEncoding.EncodeToString(k.Bytes())
	pub := base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
	cfg := `{"log":{"loglevel":"warning"},"routing":{"rules":[{"ip":["geoip:private"],"outboundTag":"BLOCK","type":"field"}]},
"inbounds":[
 {"tag":"VLESS TCP REALITY","listen":"0.0.0.0","port":443,"protocol":"vless","settings":{"clients":[],"decryption":"none"},
  "streamSettings":{"network":"tcp","tcpSettings":{},"security":"reality","realitySettings":{"show":false,"dest":"www.google.com:443","xver":0,"serverNames":["www.google.com"],"privateKey":"` + priv + `","shortIds":["ab12cd34"]}},
  "sniffing":{"enabled":true,"destOverride":["http","tls"]}},
 {"tag":"VMess TCP","listen":"0.0.0.0","port":8081,"protocol":"vmess","settings":{"clients":[]},"streamSettings":{"network":"tcp"}},
 {"tag":"VLESS WS TLS","listen":"0.0.0.0","port":8443,"protocol":"vless","settings":{"clients":[],"decryption":"none"},
  "streamSettings":{"network":"ws","wsSettings":{"path":"/ws"},"security":"tls","tlsSettings":{"serverName":"x.example.com","certificates":[{"certificateFile":"/var/lib/marzban/certs/fullchain.pem","keyFile":"/var/lib/marzban/certs/key.pem"}]}}},
 {"tag":"Trojan Websocket TLS","listen":"0.0.0.0","port":2087,"protocol":"trojan","settings":{"clients":[]},"streamSettings":{"network":"ws","wsSettings":{"path":"/t"},"security":"tls"}},
 {"tag":"Shadowsocks TCP","listen":"0.0.0.0","port":1080,"protocol":"shadowsocks","settings":{"clients":[],"network":"tcp,udp"}},
 {"tag":"API_INBOUND","listen":"127.0.0.1","port":62789,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1"}}
],"outbounds":[{"protocol":"freedom","tag":"DIRECT"}]}`
	d, err := parseXrayConfig([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range d.Inbounds {
		t.Logf("%-22s port=%-5d kind=%-14s skip=%q w=%v", i.Name, i.Port, i.Kind, i.SkipReason, i.Warnings)
		if i.Kind == "vless-reality" {
			if i.Settings.PrivateKey != priv || i.Settings.PublicKey != pub || i.Settings.SNI != "www.google.com" || i.Settings.ShortIDs == "" {
				t.Errorf("Reality: ключи/SNI не сохранились: %+v", i.Settings)
			}
		}
	}
}

func TestImportMoreUDPTCPSamePort(t *testing.T) {
	re := m{"network": "tcp", "security": "reality", "realitySettings": m{"dest": "example.com:443", "serverNames": []string{"example.com"}, "privateKey": "x", "shortIds": []string{"ab"}}}
	p := imdb(t,
		imrow{1, "RE", 443, "vless", m{"clients": []m{{"id": uuidA, "email": "u1", "subId": "s1"}}, "decryption": "none"}, re},
		imrow{2, "HY", 443, "hysteria", m{"version": 2, "clients": []m{{"auth": "pw1", "email": "u2", "subId": "s2"}}}, hyStream(nil)},
		imrow{3, "HY2", 443, "hysteria", m{"version": 2, "clients": []m{}}, hyStream(nil)},
		imrow{4, "TU", 443, "tuic", m{"users": []m{}}, nil},
	)
	k := openKitsune(t)
	data, _ := Read3XUI(p)
	rep, err := Run(k, data, opts(true, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range rep.Inbounds {
		t.Logf("%s [%s] conflict=%v details=%q reason=%q", it.Name, it.Action, it.Conflict, it.Details, it.Reason)
	}
}

// gzip-бомба: 300 МБ нулей в ответе с Content-Encoding: gzip.
func TestImportMoreAPIGzipBomb(t *testing.T) {
	var comp bytes.Buffer
	zw := gzip.NewWriter(&comp)
	zw.Write([]byte(`{"users":[{"username":"a","note":"`))
	z := make([]byte, 1<<20)
	for i := range z {
		z[i] = 'a'
	}
	for i := 0; i < 300; i++ {
		zw.Write(z)
	}
	zw.Write([]byte(`"}],"total":1}`))
	zw.Close()
	t.Logf("сжато: %d КБ", comp.Len()/1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(comp.Bytes())
	}))
	defer srv.Close()
	var ms0, ms1 runtime.MemStats
	runtime.ReadMemStats(&ms0)
	start := time.Now()
	_, err := ReadMarzbanAPI(context.Background(), srv.URL, APIAuth{Token: "t"})
	runtime.ReadMemStats(&ms1)
	t.Logf("gzip-бомба: err=%v за %v, выделено %d МБ", err, time.Since(start), (ms1.TotalAlloc-ms0.TotalAlloc)>>20)
	if err == nil {
		t.Error("бомба принята")
	}
}
