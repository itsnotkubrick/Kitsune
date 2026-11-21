package importer

import (
	"encoding/base64"
	"strings"
	"testing"

	"kitsune/internal/proto"
)

func ssKey(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }

// xui310Fixture – база 3x-ui v3.10.x после миграций первого запуска: маска udphop, протоколы masque и xdrive,
// xdns в новой форме names/addrs и Shadowsocks-2022 с aes-256-gcm.
func xui310Fixture(t *testing.T) string {
	d, p := newFile(t)
	mustExec(t, d, `CREATE TABLE inbounds (id INTEGER PRIMARY KEY, remark TEXT, enable NUMERIC, listen TEXT, port INT, protocol TEXT, settings TEXT, stream_settings TEXT, tag TEXT)`)
	hy := func(masks []m, qp m) string {
		return jsonOf(t, m{"network": "hysteria", "security": "tls",
			"tlsSettings":      m{"serverName": "hy.example.com", "certificates": []m{{"certificateFile": "/etc/ssl/hy.crt", "keyFile": "/etc/ssl/hy.key"}}},
			"hysteriaSettings": m{"version": 2},
			"finalmask":        m{"udp": masks, "quicParams": qp}})
	}
	hyUsers := jsonOf(t, m{"version": 2, "clients": []m{{"auth": "hy-pass-1", "email": "ann", "subId": "subAnn", "enable": true}}})
	// 1: Hysteria 2 с salamander и udphop (новая форма 3.10)
	mustExec(t, d, `INSERT INTO inbounds VALUES (1, 'HY-HOP', 1, '', 8443, 'hysteria', ?, ?, 'in-8443')`, hyUsers,
		hy([]m{{"type": "salamander", "settings": m{"password": "obfs-secret"}}, {"type": "udphop", "settings": m{"ports": "20000-30000", "interval": "30"}}}, m{"brutalUp": "100 mbps"}))
	// 2: Hysteria 2 со старым клиентским quicParams.udpHop (база до первого запуска 3.10)
	mustExec(t, d, `INSERT INTO inbounds VALUES (2, 'HY-OLD', 1, '', 8444, 'hysteria', ?, ?, 'in-8444')`, hyUsers,
		hy([]m{{"type": "salamander", "settings": m{"password": "obfs-secret"}}}, m{"udpHop": m{"ports": "20000-30000", "interval": "30"}}))
	// 3: Hysteria 2 без прыжков – предупреждения о прыжках быть не должно
	mustExec(t, d, `INSERT INTO inbounds VALUES (3, 'HY-PLAIN', 1, '', 8445, 'hysteria', ?, ?, 'in-8445')`, hyUsers,
		hy([]m{{"type": "salamander", "settings": m{"password": "obfs-secret"}}}, m{}))
	// 4, 5: протоколы, которых у Kitsune нет
	mustExec(t, d, `INSERT INTO inbounds VALUES (4, 'MQ', 1, '', 8446, 'masque', '{}', '{}', 'in-8446')`)
	mustExec(t, d, `INSERT INTO inbounds VALUES (5, 'XD', 1, '', 8447, 'xdrive', '{}', '{}', 'in-8447')`)
	// 6: VLESS по mKCP с xdns в новой форме names/addrs
	mustExec(t, d, `INSERT INTO inbounds VALUES (6, 'KCP-XDNS', 1, '', 8448, 'vless', ?, ?, 'in-8448')`,
		jsonOf(t, m{"clients": []m{{"id": uuidA, "email": "k", "subId": "subK", "enable": true}}}),
		jsonOf(t, m{"network": "kcp", "security": "none", "finalmask": m{"udp": []m{{"type": "xdns", "settings": m{"names": []string{"t.example.com"}, "addrs": []string{"1.1.1.1:53"}}}}}}))
	// 7, 8, 9: Shadowsocks-2022: новый шифр после миграции, прежний chacha20 и старый метод
	ss := func(method string, keyLen int) string {
		return jsonOf(t, m{"method": method, "password": ssKey(keyLen), "network": "tcp,udp", "clients": []m{}})
	}
	mustExec(t, d, `INSERT INTO inbounds VALUES (7, 'SS-AES256', 1, '', 8449, 'shadowsocks', ?, '{}', 'in-8449')`, ss("2022-blake3-aes-256-gcm", 32))
	mustExec(t, d, `INSERT INTO inbounds VALUES (8, 'SS-CHACHA', 1, '', 8450, 'shadowsocks', ?, '{}', 'in-8450')`, ss("2022-blake3-chacha20-poly1305", 32))
	mustExec(t, d, `INSERT INTO inbounds VALUES (9, 'SS-OLD', 1, '', 8451, 'shadowsocks', ?, '{}', 'in-8451')`, ss("chacha20-ietf-poly1305", 32))
	return p
}

func TestRead3XUI310(t *testing.T) {
	data, err := Read3XUI(xui310Fixture(t))
	if err != nil {
		t.Fatalf("база 3x-ui 3.10.x не читается: %v", err)
	}
	in := map[string]SrcInbound{}
	for _, i := range data.Inbounds {
		in[i.Name] = i
	}
	if len(in) != 9 {
		t.Fatalf("прочитано %d подключений из 9: %v", len(in), in)
	}
	hasHop := func(ws []string) bool {
		for _, w := range ws {
			if strings.Contains(w, "udphop") {
				return true
			}
		}
		return false
	}

	for _, name := range []string{"HY-HOP", "HY-OLD"} {
		h := in[name]
		if h.Kind != proto.Hysteria2 || h.SkipReason != "" {
			t.Fatalf("%s: должна переноситься как Hysteria 2: %+v", name, h)
		}
		if h.Settings.ObfsPassword != "obfs-secret" {
			t.Errorf("%s: пароль salamander потерян: %+v", name, h.Settings)
		}
		if !hasHop(h.Warnings) {
			t.Errorf("%s: нет предупреждения, что перескок портов не переносится: %v", name, h.Warnings)
		}
	}
	if p := in["HY-PLAIN"]; p.Kind != proto.Hysteria2 || hasHop(p.Warnings) {
		t.Errorf("HY-PLAIN: лишнее предупреждение про перескок: %+v", p)
	}
	if in["HY-HOP"].Settings.UpMbps != "100" {
		t.Errorf("ограничение скорости рядом с udphop потеряно: %+v", in["HY-HOP"].Settings)
	}

	for name, word := range map[string]string{"MQ": "masque", "XD": "xdrive"} {
		o := in[name]
		if o.Kind != "" || !strings.Contains(o.SkipReason, word) || !strings.Contains(o.SkipReason, "не переносится") {
			t.Errorf("%s: нужен понятный пропуск: %+v", name, o)
		}
		if strings.Contains(o.SkipReason, "неизвестн") {
			t.Errorf("%s: протокол назван неизвестным: %q", name, o.SkipReason)
		}
	}
	if k := in["KCP-XDNS"]; k.Kind != "" || k.SkipReason == "" {
		t.Errorf("VLESS по mKCP с xdns должен пропускаться: %+v", k)
	}

	if s := in["SS-AES256"]; s.Kind != proto.SS2022 || s.Settings.Method != "2022-blake3-aes-256-gcm" || s.Settings.ServerKey != ssKey(32) {
		t.Errorf("SS-2022 с новым шифром: %+v", s)
	}
	if s := in["SS-CHACHA"]; s.Kind != proto.SS2022 || s.Settings.Method != "2022-blake3-chacha20-poly1305" {
		t.Errorf("SS-2022 с chacha20: %+v", s)
	}
	if s := in["SS-OLD"]; s.Kind != "" || !strings.Contains(s.SkipReason, "2022") {
		t.Errorf("Shadowsocks со старым методом должен пропускаться с пояснением: %+v", s)
	}
}
