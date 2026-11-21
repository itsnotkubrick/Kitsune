package importer

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kitsune/internal/db"
	"kitsune/internal/proto"
)

func realXUI(t *testing.T) (*sql.DB, string) {
	d, p := newFile(t)
	// схема как у gorm-модели MHSanaei/3x-ui
	mustExec(t, d, `CREATE TABLE inbounds (id integer PRIMARY KEY AUTOINCREMENT, user_id integer, up integer, down integer, total integer, remark text, enable numeric, expiry_time integer, traffic_reset text DEFAULT "never", last_traffic_reset_time integer DEFAULT 0, listen text, port integer, protocol text, settings text, stream_settings text, tag text UNIQUE, sniffing text)`)
	mustExec(t, d, `CREATE TABLE client_traffics (id integer PRIMARY KEY AUTOINCREMENT, inbound_id integer, enable numeric, email text UNIQUE, up integer, down integer, expiry_time integer, total integer, reset integer DEFAULT 0, all_time integer, last_online integer)`)
	return d, p
}

func addInbound(t *testing.T, d *sql.DB, remark string, port int, proto_, settings, stream string) {
	mustExec(t, d, `INSERT INTO inbounds (remark, enable, port, protocol, settings, stream_settings, tag) VALUES (?, 1, ?, ?, ?, ?, ?)`, remark, port, proto_, settings, stream, fmt.Sprintf("in-%d-%s", port, remark))
}

func realityStream(t *testing.T, key string) string {
	priv, pub, _ := proto.RealityKeys()
	return jsonOf(t, m{"network": "tcp", "security": "reality", "realitySettings": m{
		key: "www.example.com:443", "serverNames": []string{"www.example.com"}, "privateKey": priv, "shortIds": []string{"ab"},
		"settings": m{"publicKey": pub, "fingerprint": "chrome", "serverName": "", "spiderX": "/"}}})
}

// 3x-ui новых версий пишет "target", старых "dest".
func TestImportEdgeRealityTargetKey(t *testing.T) {
	for _, key := range []string{"dest", "target"} {
		d, p := realXUI(t)
		addInbound(t, d, "r", 443, "vless", `{"clients":[]}`, realityStream(t, key))
		data, err := Read3XUI(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := data.Inbounds[0].Settings.Target; got != "www.example.com:443" {
			t.Errorf("ключ %q: Target=%q", key, got)
		}
	}
}

func TestImportEdgeBoundaries(t *testing.T) {
	d, p := realXUI(t)
	cl := []m{}
	add := func(email string, total, exp int64, extra m) {
		c := m{"id": uuidA[:35] + fmt.Sprint(len(cl)), "email": email, "totalGB": total, "expiryTime": exp, "enable": true, "subId": "s" + email}
		for k, v := range extra {
			c[k] = v
		}
		cl = append(cl, c)
	}
	add("zero", 0, 0, nil)
	add("max", maxTraffic, maxExpiryMs, nil)
	add("overT", maxTraffic+1, 0, nil)
	add("overE", 0, maxExpiryMs+1, nil)
	add("negE", 0, -1, nil)
	add("negMax", 0, -maxExpiryMs, nil)
	add("one", 1, 1, nil)
	add("past", 0, 1000, nil)
	add("ipHuge", 0, 0, m{"limitIp": 1 << 40})
	addInbound(t, d, "r", 443, "vless", jsonOf(t, m{"clients": cl}), realityStream(t, "dest"))
	data, err := Read3XUI(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range data.Users {
		t.Logf("%-8s limit=%d exp=%d delayed=%d ip=%d warn=%v", u.Name, u.TrafficLimit, u.ExpiryMs, u.DelayedMs, u.IPLimit, u.Warnings)
	}
	k := openKitsune(t)
	rep, err := Run(k, data, opts(true, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range rep.Users {
		t.Logf("%s %s | %s | %s", it.Action, it.Name, it.Details, it.Reason)
	}
}

func TestImportEdgeTextAbuse(t *testing.T) {
	d, p := newFile(t)
	mustExec(t, d, `CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, status TEXT, used_traffic INT, data_limit INT, expire INT, note TEXT, on_hold_expire_duration INT)`)
	names := []string{"😀😀", "Иван", "Пётр", "a‮b", "​​", "x\x00y", strings.Repeat("я", 5000), strings.Repeat("a", 5000), "ADMIN", "admin", "a@x", "a@y", "<script>alert(1)</script>", "../../etc/passwd", "", "   ", "a b", "a_b", "a-b"}
	for i, n := range names {
		mustExec(t, d, `INSERT INTO users (username, status, used_traffic, data_limit, expire, note) VALUES (?, 'active', -5, NULL, NULL, ?)`, n, strings.Repeat("<img src=x onerror=alert(1)>", 100))
		_ = i
	}
	data, err := ReadMarzban(p)
	if err != nil {
		t.Fatal(err)
	}
	k := openKitsune(t)
	rep, err := Run(k, data, opts(true, false))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, it := range rep.Users {
		t.Logf("%-8s %q | %s", it.Action, it.Name, it.Reason)
		if it.Action == ActCreate {
			if seen[it.Name] {
				t.Errorf("дубль имени %q", it.Name)
			}
			seen[it.Name] = true
		}
	}
	var n int
	k.QueryRow(`SELECT COUNT(*) FROM users WHERE note LIKE '%<%' OR name LIKE '%<%'`).Scan(&n)
	t.Logf("в базе строк с '<': %d (в базу попадает как текст, XSS проверять на выводе)", n)
	var maxn int
	k.QueryRow(`SELECT MAX(LENGTH(note)) FROM users`).Scan(&maxn)
	if maxn > 4*maxNoteRunes {
		t.Errorf("заметка слишком длинная: %d", maxn)
	}
}

func TestImportEdgeReimportAndUpdate(t *testing.T) {
	d, p := newFile(t)
	mustExec(t, d, `CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, status TEXT, used_traffic INT, data_limit INT, expire INT, note TEXT, on_hold_expire_duration INT)`)
	mustExec(t, d, `CREATE TABLE proxies (id INTEGER PRIMARY KEY, user_id INT, type TEXT, settings TEXT)`)
	mustExec(t, d, `INSERT INTO users VALUES (1,'ivan','on_hold',10,NULL,0,'n',86400)`)
	mustExec(t, d, `INSERT INTO proxies VALUES (1,1,'VLESS','{"id":"`+uuidA+`","flow":""}')`)
	k := openKitsune(t)
	now := fixedNow
	o := Options{Apply: true, Update: true, Now: func() time.Time { return now }}
	data, _ := ReadMarzban(p)
	if _, err := Run(k, data, o); err != nil {
		t.Fatal(err)
	}
	var e1, e2 int64
	k.QueryRow(`SELECT expiry_time FROM users WHERE name='ivan'`).Scan(&e1)
	now = now.Add(48 * time.Hour)
	o.Now = func() time.Time { return now }
	rep, err := Run(k, data, o)
	if err != nil {
		t.Fatal(err)
	}
	k.QueryRow(`SELECT expiry_time FROM users WHERE name='ivan'`).Scan(&e2)
	t.Logf("итог повторного: %+v; срок 1=%d, срок 2=%d (сдвиг %d ч)", rep.UserSum, e1, e2, (e2-e1)/3600000)
	if e1 != e2 {
		t.Errorf("повторный --update сдвигает срок отложенного старта на %d ч", (e2-e1)/3600000)
	}
	if count(t, k, "users") != 1 {
		t.Error("дубль пользователя")
	}
}

func TestImportEdgeWAL(t *testing.T) {
	// база в режиме WAL с непринятыми записями в -wal рядом
	dir := t.TempDir()
	p := filepath.Join(dir, "x-ui.db")
	d, err := sql.Open("sqlite", "file:"+p+"?_pragma=journal_mode(WAL)&_pragma=wal_autocheckpoint(0)")
	if err != nil {
		t.Fatal(err)
	}
	d.SetMaxOpenConns(1)
	mustExec(t, d, `CREATE TABLE inbounds (id integer primary key, port int, protocol text, settings text)`)
	mustExec(t, d, `INSERT INTO inbounds VALUES (1, 443, 'vless', '{"clients":[{"id":"`+uuidA+`","email":"walluser","subId":"walls"}]}')`)
	st, _ := os.Stat(p + "-wal")
	if st == nil || st.Size() == 0 {
		t.Skip("wal не создался")
	}
	data, err := Read3XUI(p) // d ещё открыта: журнал не слит
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Users) != 1 {
		t.Errorf("записи из WAL не прочитаны: %d", len(data.Users))
	}
	d.Close()
}

func TestImportEdgeDuplicatesAndSubGroups(t *testing.T) {
	d, p := realXUI(t)
	cl := []m{
		{"id": uuidA, "email": "u1", "subId": "same", "totalGB": 0, "expiryTime": 0, "enable": true},
		{"id": uuidA, "email": "u2", "subId": "same", "totalGB": 100, "expiryTime": 5000000000000, "enable": true},
		{"id": uuidB, "email": "U1", "subId": "other", "enable": true},
		{"id": uuidB, "email": "u3", "subId": "Same", "enable": true},
		{"id": uuidB, "email": "tr1", "password": "p1", "enable": true},
		{"id": uuidB, "email": "tr1@x", "password": "p2", "enable": true},
	}
	addInbound(t, d, "r", 443, "vless", jsonOf(t, m{"clients": cl}), realityStream(t, "target"))
	data, err := Read3XUI(p)
	if err != nil {
		t.Fatal(err)
	}
	k := openKitsune(t)
	rep, err := Run(k, data, opts(true, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range data.Users {
		t.Logf("src %q sub=%q uuid=%q limit=%d exp=%d warn=%v", u.Name, u.SubID, u.UUID, u.TrafficLimit, u.ExpiryMs, u.Warnings)
	}
	for _, it := range rep.Users {
		t.Logf("%s %q | %s", it.Action, it.Name, it.Reason)
	}
	var n int
	k.QueryRow(`SELECT COUNT(*) FROM (SELECT uuid FROM users GROUP BY uuid HAVING COUNT(*)>1)`).Scan(&n)
	if n > 0 {
		t.Errorf("в Kitsune два пользователя с одним uuid (%d групп)", n)
	}
}

func TestImportEdgePortsAndKinds(t *testing.T) {
	d, p := realXUI(t)
	rs := realityStream(t, "target")
	addInbound(t, d, "a", 443, "vless", `{"clients":[]}`, rs)
	addInbound(t, d, "b", 443, "vless", `{"clients":[]}`, rs) // тот же порт и тип в самой базе
	addInbound(t, d, "c", 0, "vless", `{"clients":[]}`, rs)
	addInbound(t, d, "d", 65536, "vless", `{"clients":[]}`, rs)
	addInbound(t, d, "e", 8080, "vless", `{"clients":[]}`, rs) // порт панели
	addInbound(t, d, "f", 10085, "vless", `{"clients":[]}`, rs)
	addInbound(t, d, "g", 2000, "vless", `{"clients":[]}`, `{"network":"kcp","security":"none"}`)
	addInbound(t, d, "h", 2001, "wireguard", `{}`, `{}`)
	addInbound(t, d, "i", 2002, "VLESS", `not json`, `{{{`)
	addInbound(t, d, "j", 2003, "weird", `{}`, `{}`)
	addInbound(t, d, "k", 2004, "shadowsocks", `{"method":"aes-256-gcm","password":"x"}`, `{}`)
	addInbound(t, d, "", 2005, "vmess", `{}`, `{"network":"ws","security":"tls","wsSettings":{"path":"/../x"}}`)
	mustExec(t, d, `INSERT INTO inbounds (remark, enable, port, protocol, settings, stream_settings, tag) VALUES (NULL,1,2006,'vless',NULL,NULL,NULL)`)
	data, err := Read3XUI(p)
	if err != nil {
		t.Fatal(err)
	}
	k := openKitsune(t)
	o := opts(true, false)
	o.PortReserved = func(port int, n string) bool { return port == 8080 || port == 10085 }
	rep, err := Run(k, data, o)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range rep.Inbounds {
		t.Logf("%s %q | %s | %s | конфликт=%v", it.Action, it.Name, it.Details, it.Reason, it.Conflict)
	}
	// порт один и тот же на двух create в одном прогоне
	var dup int
	k.QueryRow(`SELECT COUNT(*) FROM (SELECT port, kind FROM inbounds GROUP BY port, kind HAVING COUNT(*)>1)`).Scan(&dup)
	if dup > 0 {
		t.Errorf("созданы два подключения с одним портом и типом")
	}
}

func TestImportEdgeConcurrentRuns(t *testing.T) {
	d, p := newFile(t)
	mustExec(t, d, `CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, status TEXT, used_traffic INT, data_limit INT, expire INT, note TEXT, on_hold_expire_duration INT)`)
	for i := 0; i < 50; i++ {
		mustExec(t, d, `INSERT INTO users (username) VALUES (?)`, fmt.Sprint("u", i))
	}
	k := openKitsune(t)
	data, _ := ReadMarzban(p)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := Run(k, data, opts(true, false))
			t.Logf("err=%v", err)
		}()
	}
	wg.Wait()
	if n := count(t, k, "users"); n != 50 {
		t.Errorf("после 4 параллельных прогонов пользователей %d", n)
	}
}

func TestImportEdgeBig(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	d, p := newFile(t)
	mustExec(t, d, `CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, status TEXT, used_traffic INT, data_limit INT, expire INT, note TEXT, on_hold_expire_duration INT)`)
	mustExec(t, d, `BEGIN`)
	for i := 0; i < 100000; i++ {
		mustExec(t, d, `INSERT INTO users (username, status, used_traffic) VALUES (?, 'active', 5)`, fmt.Sprint("user", i))
	}
	mustExec(t, d, `COMMIT`)
	k := openKitsune(t)
	t0 := time.Now()
	data, err := ReadMarzban(p)
	if err != nil {
		t.Fatal(err)
	}
	t1 := time.Now()
	rep, err := Run(k, data, opts(false, false))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("чтение %v, пробный %v, пользователей %d", t1.Sub(t0), time.Since(t1), rep.UserSum.Create)
	t2 := time.Now()
	if _, err := Run(k, data, opts(true, false)); err != nil {
		t.Fatal(err)
	}
	t.Logf("запись %v", time.Since(t2))
	d.Exec(`INSERT INTO users (username) VALUES ('one-more')`)
	if _, err := ReadMarzban(p); err == nil {
		t.Error("100001 пользователь принят")
	}
}

func TestImportEdgeNewSchemaPasswordProtocol(t *testing.T) {
	d, p := newFile(t)
	mustExec(t, d, `CREATE TABLE inbounds (id INTEGER PRIMARY KEY, remark TEXT, enable NUMERIC, port INT, protocol TEXT, settings TEXT, stream_settings TEXT, tag TEXT)`)
	mustExec(t, d, `CREATE TABLE clients (id INTEGER PRIMARY KEY, email TEXT, sub_id TEXT, uuid TEXT, password TEXT, flow TEXT, limit_ip INT, total_gb INT, expiry_time INT, enable NUMERIC, comment TEXT)`)
	// клиент Shadowsocks (пароль = ключ SS), без trojan-подключений
	mustExec(t, d, `INSERT INTO clients (email, sub_id, uuid, password, enable) VALUES ('ss1', 'sss', '', 'SSKEYBASE64AAAA==', 1)`)
	data, err := Read3XUI(p)
	if err != nil {
		t.Fatal(err)
	}
	if data.Users[0].Password != "" {
		t.Errorf("пароль не-Trojan клиента (Shadowsocks) стал паролем Trojan: %q", data.Users[0].Password)
	}
}

func TestImportEdgeMergeUnlimited(t *testing.T) {
	d, p := realXUI(t)
	addInbound(t, d, "a", 443, "vless", jsonOf(t, m{"clients": []m{
		{"id": uuidA, "email": "x1", "subId": "S", "totalGB": 0, "expiryTime": 0, "enable": true}}}), realityStream(t, "dest"))
	addInbound(t, d, "b", 444, "vless", jsonOf(t, m{"clients": []m{
		{"id": uuidA, "email": "x2", "subId": "S", "totalGB": 5 << 30, "expiryTime": 1900000000000, "enable": true}}}), realityStream(t, "dest"))
	data, _ := Read3XUI(p)
	u := data.Users[0]
	t.Logf("limit=%d exp=%d warn=%v", u.TrafficLimit, u.ExpiryMs, u.Warnings)
	if u.TrafficLimit != 0 || u.ExpiryMs != 0 {
		t.Errorf("безлимитный клиент в одном подключении и ограниченный в другом стал ограниченным (limit=%d exp=%d) без предупреждения: %v", u.TrafficLimit, u.ExpiryMs, u.Warnings)
	}
}

func TestImportEdgeSyncMembershipAfterImport(t *testing.T) {
	d, p := realXUI(t)
	addInbound(t, d, "a", 443, "vless", jsonOf(t, m{"clients": []m{
		{"id": uuidA, "email": "x1", "subId": "S1", "enable": true},
		{"id": uuidB, "email": "x2", "subId": "S2", "enable": true}}}), realityStream(t, "dest"))
	addInbound(t, d, "b", 8443, "vless", jsonOf(t, m{"clients": []m{}}), realityStream(t, "dest"))
	mustExec(t, d, `INSERT INTO client_traffics (email, up, down) VALUES ('x1', 1000, 2000)`)
	data, _ := Read3XUI(p)
	k := openKitsune(t)
	if _, err := Run(k, data, opts(true, false)); err != nil {
		t.Fatal(err)
	}
	var before int
	k.QueryRow(`SELECT COUNT(*) FROM clients`).Scan(&before)
	if err := db.SyncMembership(); err != nil {
		t.Fatal(err)
	}
	var after, used int
	k.QueryRow(`SELECT COUNT(*) FROM clients`).Scan(&after)
	k.QueryRow(`SELECT COALESCE(SUM(used_traffic),0) FROM clients`).Scan(&used)
	var dup int
	k.QueryRow(`SELECT COUNT(*) FROM (SELECT inbound_id, user_id FROM clients GROUP BY 1,2 HAVING COUNT(*)>1)`).Scan(&dup)
	t.Logf("clients до sync %d, после %d, трафик %d, дублей %d", before, after, used, dup)
	if used != 3000 || dup != 0 || after != 4 {
		t.Errorf("после SyncMembership: used=%d dup=%d clients=%d", used, dup, after)
	}
}

// Злонамеренная база: «таблица» inbounds – вид с бесконечной рекурсией. ORDER BY заставляет считать всё.
func TestImportEdgeHostileView(t *testing.T) {
	d, p := newFile(t)
	mustExec(t, d, `CREATE VIEW inbounds AS WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT x AS id, 443 AS port, 'vless' AS protocol, '{}' AS settings FROM c`)
	done := make(chan error, 1)
	go func() { _, err := Read3XUI(p); done <- err }()
	select {
	case err := <-done:
		t.Logf("завершилось: %v", err)
	case <-time.After(15 * time.Second):
		t.Errorf("чтение вредоносной базы не завершилось за 15 с (нет ограничения по времени/памяти)")
	}
}

func TestImportEdgePerms(t *testing.T) {
	d, p := realXUI(t)
	addInbound(t, d, "a", 443, "vless", `{"clients":[]}`, `{}`)
	d.Close()
	os.Chmod(p, 0)
	defer os.Chmod(p, 0o600)
	_, err := Read3XUI(p)
	t.Logf("chmod 000: %v", err)
	if err == nil {
		t.Skip("читается (root?)")
	}
	dir := filepath.Dir(p)
	_, err = Read3XUI(dir)
	t.Logf("каталог: %v", err)
	ln := filepath.Join(t.TempDir(), "link.db")
	os.Chmod(p, 0o600)
	os.Symlink(p, ln)
	_, err = Read3XUI(ln)
	t.Logf("symlink: %v", err)
}

// Разные пользователи источника, чьи имена после очистки совпали (a@x / a@y, "a b" / "a_b"), без uuid и subId.
func TestImportEdgeNameCollisionLosesUser(t *testing.T) {
	d, p := newFile(t)
	mustExec(t, d, `CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, status TEXT, used_traffic INT, data_limit INT, expire INT, note TEXT, on_hold_expire_duration INT)`)
	for _, n := range []string{"a@x", "a@y", "a b", "a_b"} {
		mustExec(t, d, `INSERT INTO users (username, status) VALUES (?, 'active')`, n)
	}
	data, _ := ReadMarzban(p)
	k := openKitsune(t)
	if _, err := Run(k, data, opts(true, false)); err != nil {
		t.Fatal(err)
	}
	if n := count(t, k, "users"); n != 4 {
		t.Errorf("из 4 разных пользователей источника создано %d (остальные молча отнесены к «дублям»)", n)
	}
}
