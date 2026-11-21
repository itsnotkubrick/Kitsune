package importer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"kitsune/internal/db"
	"kitsune/internal/proto"
)

const (
	uuidA = "11111111-2222-4333-8444-555555555555"
	uuidB = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
)

var fixedNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func mustExec(t *testing.T, d *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := d.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func newFile(t *testing.T) (*sql.DB, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "src.db")
	d, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	d.SetMaxOpenConns(1)
	t.Cleanup(func() { d.Close() })
	return d, p
}

func jsonOf(t *testing.T, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type m = map[string]any

// xuiFixture – база 3x-ui старой схемы (клиенты внутри JSON подключений).
func xuiFixture(t *testing.T) string {
	d, p := newFile(t)
	mustExec(t, d, `CREATE TABLE inbounds (id INTEGER PRIMARY KEY, user_id INT, up INT, down INT, total INT, remark TEXT, enable NUMERIC,
		expiry_time INT, listen TEXT, port INT UNIQUE, protocol TEXT, settings TEXT, stream_settings TEXT, tag TEXT, sniffing TEXT)`)
	mustExec(t, d, `CREATE TABLE client_traffics (id INTEGER PRIMARY KEY, inbound_id INT, enable NUMERIC, email TEXT UNIQUE, up INT, down INT, expiry_time INT, total INT)`)
	mustExec(t, d, `CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)`)
	mustExec(t, d, `INSERT INTO users VALUES (1, 'admin', 'secret-admin-pass')`)
	priv, pub, _ := proto.RealityKeys()
	reality := jsonOf(t, m{"network": "tcp", "security": "reality", "realitySettings": m{
		"dest": "www.example.com:443", "serverNames": []string{"www.example.com"}, "privateKey": priv, "shortIds": []string{"ab12cd34", "zz"},
		"settings": m{"publicKey": pub, "fingerprint": "chrome"}}})
	mustExec(t, d, `INSERT INTO inbounds (id, remark, enable, port, protocol, settings, stream_settings, tag) VALUES (1, 'Main Reality', 1, 443, 'vless', ?, ?, 'in-443')`,
		jsonOf(t, m{"clients": []m{
			{"id": uuidA, "email": "alice@x", "flow": "xtls-rprx-vision", "limitIp": 2, "totalGB": 10 << 30, "expiryTime": 1800000000000, "enable": true, "subId": "subAlice1", "comment": "друг‮ Алисы"},
			{"id": uuidB, "email": "bob", "totalGB": "0", "expiryTime": -604800000, "enable": false, "subId": "subBob"},
			{"id": "not-a-uuid", "email": "carol", "totalGB": -5, "expiryTime": 0, "enable": true, "subId": "bad sub!"},
			{"id": uuidB, "email": "huge", "totalGB": 0, "expiryTime": 99999999999999999, "enable": true, "subId": "subHuge"},
		}}), reality)
	mustExec(t, d, `INSERT INTO inbounds (id, remark, enable, port, protocol, settings, stream_settings, tag) VALUES (2, 'Trojan', 1, 2083, 'trojan', ?, ?, 'in-2083')`,
		jsonOf(t, m{"clients": []m{{"password": "trojanpass", "email": "alice-trojan", "totalGB": 20 << 30, "expiryTime": 1700000000000, "enable": true, "subId": "subAlice1"}}}),
		jsonOf(t, m{"network": "grpc", "security": "tls", "grpcSettings": m{"serviceName": "svc1"}, "tlsSettings": m{"certificates": []m{{"certificateFile": "/etc/c.pem", "keyFile": "/etc/k.pem"}}}}))
	mustExec(t, d, `INSERT INTO inbounds (id, remark, enable, port, protocol, settings, stream_settings, tag) VALUES (3, 'Plain vmess', 1, 8080, 'vmess', '{"clients":[]}', '{"network":"tcp","security":"none"}', 'in-8080')`)
	mustExec(t, d, `INSERT INTO inbounds (id, remark, enable, port, protocol, settings, stream_settings, tag) VALUES (4, 'Hy', 1, 4433, 'hysteria', '{"clients":[]}', '{}', 'in-4433')`)
	mustExec(t, d, `INSERT INTO inbounds (id, remark, enable, port, protocol, settings, stream_settings, tag) VALUES (5, 'Dup port ws', 1, 9999, 'vmess', '{"clients":[]}', ?, 'in-9999')`,
		jsonOf(t, m{"network": "ws", "security": "tls", "wsSettings": m{"path": "/ws", "headers": m{"Host": "h.example.com"}}}))
	for email, ud := range map[string][2]int64{"alice@x": {100, 200}, "alice-trojan": {1000, 2000}, "bob": {0, 0}} {
		mustExec(t, d, `INSERT INTO client_traffics (email, up, down) VALUES (?, ?, ?)`, email, ud[0], ud[1])
	}
	return p
}

func TestRead3XUI(t *testing.T) {
	data, err := Read3XUI(xuiFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	users := map[string]SrcUser{}
	for _, u := range data.Users {
		users[u.Name] = u
	}
	if len(data.Users) != 4 {
		t.Fatalf("пользователей %d, ждали 4 (alice+alice-trojan склеены): %+v", len(data.Users), data.Users)
	}
	a := users["alice@x"]
	if a.UUID != uuidA || a.SubID != "subAlice1" || !a.Vision || !a.Enable || a.IPLimit != 2 {
		t.Errorf("alice: %+v", a)
	}
	if a.TrafficLimit != 20<<30 || a.ExpiryMs != 1800000000000 {
		t.Errorf("наибольшие лимит и срок: %+v", a)
	}
	if a.Used != 3300 { // 100+200 + 1000+2000
		t.Errorf("использовано %d, ждали 3300", a.Used)
	}
	if a.Password != "trojanpass" {
		t.Errorf("пароль trojan не взят")
	}
	if strings.Contains(a.Note, "‮") || a.Note != "друг Алисы" {
		t.Errorf("заметка не очищена: %q", a.Note)
	}
	if b := users["bob"]; b.Enable || b.DelayedMs != 604800000 || b.ExpiryMs != 0 || b.TrafficLimit != 0 {
		t.Errorf("bob: %+v", b)
	}
	if c := users["carol"]; c.UUID != "" || c.SubID != "" || c.TrafficLimit != -1 || len(c.Warnings) < 2 {
		t.Errorf("carol: %+v", c)
	}
	if h := users["huge"]; h.ExpiryMs != -1 {
		t.Errorf("huge: %+v", h)
	}
	kinds := map[string]SrcInbound{}
	for _, i := range data.Inbounds {
		kinds[i.Name] = i
	}
	r := kinds["Main Reality"]
	if r.Kind != proto.VlessReality || r.Settings.SNI != "www.example.com" || r.Settings.ShortIDs != "ab12cd34" || r.Settings.PublicKey == "" {
		t.Errorf("reality: %+v", r)
	}
	if tr := kinds["Trojan"]; tr.Kind != proto.TrojanGRPC || tr.Settings.CertMode != "custom" || tr.Settings.ServiceName != "svc1" {
		t.Errorf("trojan: %+v", tr)
	}
	if v := kinds["Plain vmess"]; v.Kind != "" || v.SkipReason == "" {
		t.Errorf("vmess tcp должен быть пропущен: %+v", v)
	}
	if h := kinds["Hy"]; h.Kind != "" || h.SkipReason == "" {
		t.Errorf("hysteria: %+v", h)
	}
	if w := kinds["Dup port ws"]; w.Kind != proto.VmessWS || w.Settings.Host != "h.example.com" || w.Settings.CertMode != "self" {
		t.Errorf("ws: %+v", w)
	}
}

func TestRead3XUINewSchema(t *testing.T) {
	d, p := newFile(t)
	mustExec(t, d, `CREATE TABLE inbounds (id INTEGER PRIMARY KEY, remark TEXT, enable NUMERIC, port INT, protocol TEXT, settings TEXT, stream_settings TEXT, tag TEXT)`)
	mustExec(t, d, `CREATE TABLE clients (id INTEGER PRIMARY KEY, email TEXT, sub_id TEXT, uuid TEXT, password TEXT, flow TEXT, limit_ip INT, total_gb INT, expiry_time INT, enable NUMERIC, comment TEXT)`)
	mustExec(t, d, `CREATE TABLE client_traffics (id INTEGER PRIMARY KEY, email TEXT, up INT, down INT)`)
	mustExec(t, d, `INSERT INTO clients (email, sub_id, uuid, flow, limit_ip, total_gb, expiry_time, enable) VALUES ('n1', 'sn1', ?, '', 0, 5, 1900000000000, 1)`, uuidA)
	mustExec(t, d, `INSERT INTO client_traffics (email, up, down) VALUES ('n1', 7, 8)`)
	data, err := Read3XUI(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Users) != 1 || data.Users[0].Used != 15 || data.Users[0].UUID != uuidA || data.Users[0].SubID != "sn1" {
		t.Fatalf("%+v", data.Users)
	}
}

func marzbanFixture(t *testing.T) string {
	d, p := newFile(t)
	mustExec(t, d, `CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, status TEXT, used_traffic INT, data_limit INT, expire INT, note TEXT, on_hold_expire_duration INT)`)
	mustExec(t, d, `CREATE TABLE proxies (id INTEGER PRIMARY KEY, user_id INT, type TEXT, settings TEXT)`)
	mustExec(t, d, `CREATE TABLE inbounds (id INTEGER PRIMARY KEY, tag TEXT)`)
	mustExec(t, d, `INSERT INTO inbounds (tag) VALUES ('VLESS TCP REALITY')`)
	mustExec(t, d, `INSERT INTO users VALUES (1, 'ivan', 'active', 5000, 1073741824, 1800000000, 'vip', NULL)`)
	mustExec(t, d, `INSERT INTO users VALUES (2, 'held', 'on_hold', 0, NULL, NULL, '', 86400)`)
	mustExec(t, d, `INSERT INTO users VALUES (3, 'off', 'disabled', 1, 0, 0, NULL, NULL)`)
	mustExec(t, d, `INSERT INTO users VALUES (4, 'Иван', 'active', 0, 0, 0, NULL, NULL)`)
	mustExec(t, d, `INSERT INTO users VALUES (5, 'neg', 'active', -4, -1, NULL, NULL, NULL)`)
	mustExec(t, d, `INSERT INTO proxies (user_id, type, settings) VALUES (1, 'VLESS', ?)`, `{"id":"`+uuidA+`","flow":"xtls-rprx-vision"}`)
	mustExec(t, d, `INSERT INTO proxies (user_id, type, settings) VALUES (1, 'Trojan', '{"password":"tp"}')`)
	mustExec(t, d, `INSERT INTO proxies (user_id, type, settings) VALUES (2, 'Trojan', 'не json')`)
	return p
}

func TestReadMarzban(t *testing.T) {
	data, err := ReadMarzban(marzbanFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	u := map[string]SrcUser{}
	for _, x := range data.Users {
		u[x.Name] = x
	}
	i := u["ivan"]
	if i.UUID != uuidA || !i.Vision || i.Password != "tp" || i.ExpiryMs != 1800000000000 || i.TrafficLimit != 1<<30 || i.Used != 5000 || i.Note != "vip" {
		t.Errorf("ivan: %+v", i)
	}
	if h := u["held"]; h.DelayedMs != 86400000 || !h.Enable {
		t.Errorf("held: %+v", h)
	}
	if o := u["off"]; o.Enable {
		t.Errorf("off: %+v", o)
	}
	if n := u["neg"]; n.TrafficLimit != -1 || n.Used != 0 {
		t.Errorf("neg: %+v", n)
	}
	if len(data.Inbounds) != 1 || data.Inbounds[0].Kind != "" {
		t.Errorf("подключения Marzban должны быть только справкой: %+v", data.Inbounds)
	}
}

func TestBadFiles(t *testing.T) {
	dir := t.TempDir()
	txt := filepath.Join(dir, "a.db")
	os.WriteFile(txt, []byte("это не база данных, совсем"), 0o600)
	trunc := filepath.Join(dir, "b.db")
	os.WriteFile(trunc, append([]byte("SQLite format 3\x00"), make([]byte, 40)...), 0o600)
	_, other := newFile(t) // пустая SQLite без нужных таблиц
	mustExec(t, func() *sql.DB { d, _ := sql.Open("sqlite", "file:"+other); return d }(), `CREATE TABLE x (a INT)`)
	for name, p := range map[string]string{"текст": txt, "обрезанный": trunc, "чужая схема": other, "нет файла": filepath.Join(dir, "none.db")} {
		if _, err := Read3XUI(p); err == nil {
			t.Errorf("%s: 3x-ui принял файл", name)
		}
		if _, err := ReadMarzban(p); err == nil {
			t.Errorf("%s: Marzban принял файл", name)
		}
	}
	// Оригинал не меняется и рядом ничего не появляется.
	src := xuiFixture(t)
	before, _ := os.ReadFile(src)
	if _, err := Read3XUI(src); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(src)
	if string(before) != string(after) {
		t.Error("исходная база изменилась")
	}
	ents, _ := os.ReadDir(filepath.Dir(src))
	if len(ents) != 1 {
		t.Errorf("рядом с базой появились файлы: %v", ents)
	}
}

func TestCleanText(t *testing.T) {
	cases := map[string]string{
		"  a​b‮c\x00 d  ": "abc d",
		"line1\nline2\t3": "line1 line2 3",
		"\xff\xfeok":      "ok",
	}
	for in, want := range cases {
		if got := cleanText(in, 50); got != want {
			t.Errorf("%q -> %q, ждали %q", in, got, want)
		}
	}
	if got := cleanText(strings.Repeat("я", 500), 10); len([]rune(got)) != 10 {
		t.Errorf("длина не ограничена: %d", len([]rune(got)))
	}
	if n, o := userName("Иван"); !strings.HasPrefix(n, "user_") || o != "Иван" {
		t.Errorf("имя кириллицей: %q %q", n, o)
	}
	if a, _ := userName("Иван"); a != func() string { b, _ := userName("Иван"); return b }() {
		t.Error("имя должно быть стабильным")
	}
	if n, _ := userName("bob@example.com"); n != "bob" {
		t.Errorf("%q", n)
	}
}

// openKitsune готовит рабочую базу Kitsune во временной папке.
func openKitsune(t *testing.T) *sql.DB {
	t.Helper()
	t.Chdir(t.TempDir())
	db.InitDB()
	t.Cleanup(func() { _ = db.DB.Close() })
	return db.DB
}

func count(t *testing.T, d *sql.DB, table string) int {
	var n int
	if err := d.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func opts(apply, update bool) Options {
	return Options{Apply: apply, Update: update, Now: func() time.Time { return fixedNow }}
}

func TestDryRunWritesNothingAndMasks(t *testing.T) {
	k := openKitsune(t)
	data, _ := Read3XUI(xuiFixture(t))
	u0, i0 := count(t, k, "users"), count(t, k, "inbounds")
	rep, err := Run(k, data, opts(false, false))
	if err != nil {
		t.Fatal(err)
	}
	if count(t, k, "users") != u0 || count(t, k, "inbounds") != i0 || count(t, k, "clients") != 0 {
		t.Fatal("пробный прогон записал в базу")
	}
	if rep.Applied || rep.UserSum.Create != 2 || rep.UserSum.Skip != 2 {
		t.Errorf("users: %+v", rep.UserSum)
	}
	// reality, trojan, ws – создаются; vmess tcp и hysteria – пропуск
	if rep.InSum.Create != 3 || rep.InSum.Skip != 2 {
		t.Errorf("inbounds: %+v", rep.InSum)
	}
	raw, _ := json.Marshal(rep)
	for _, secret := range []string{uuidA, uuidB, "subAlice1", "trojanpass", "ab12cd34", "secret-admin-pass"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("в отчёте открытый секрет %q", secret)
		}
	}
}

func TestApplyIdempotentAndTraffic(t *testing.T) {
	k := openKitsune(t)
	src := xuiFixture(t)
	data, _ := Read3XUI(src)
	rep, err := Run(k, data, opts(true, false))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Applied || rep.UserSum.Create != 2 || rep.InSum.Create != 3 {
		t.Fatalf("%+v %+v", rep.UserSum, rep.InSum)
	}
	if count(t, k, "users") != 2 || count(t, k, "inbounds") != 3 {
		t.Fatal("не создано")
	}
	var uid, sub string
	var used, exp, lim int64
	if err := k.QueryRow(`SELECT uuid, sub_id, traffic_limit, expiry_time FROM users WHERE name = 'alice'`).Scan(&uid, &sub, &lim, &exp); err != nil {
		t.Fatal(err)
	}
	if uid != uuidA || sub != "subAlice1" || lim != 20<<30 || exp != 1800000000000 {
		t.Errorf("alice в Kitsune: %s %s %d %d", uid, sub, lim, exp)
	}
	_ = k.QueryRow(`SELECT COALESCE(SUM(used_traffic),0) FROM clients c JOIN users u ON u.id = c.user_id WHERE u.name = 'alice'`).Scan(&used)
	if used != 3300 {
		t.Errorf("трафик alice %d", used)
	}
	// отложенный старт: now + 7 дней
	_ = k.QueryRow(`SELECT expiry_time FROM users WHERE name = 'bob'`).Scan(&exp)
	if want := fixedNow.Add(7 * 24 * time.Hour).UnixMilli(); exp != want {
		t.Errorf("bob срок %d, ждали %d", exp, want)
	}
	// Повтор не плодит дубли.
	rep2, err := Run(k, data, opts(true, false))
	if err != nil {
		t.Fatal(err)
	}
	if rep2.UserSum.Create != 0 || rep2.UserSum.Exists != 2 || rep2.InSum.Create != 0 || rep2.InSum.Exists != 3 {
		t.Errorf("повтор: %+v %+v", rep2.UserSum, rep2.InSum)
	}
	if count(t, k, "users") != 2 || count(t, k, "inbounds") != 3 {
		t.Error("повторный импорт создал дубли")
	}
	// Режим «обновлять» меняет лимит, но не трафик.
	mustExec(t, k, `UPDATE users SET traffic_limit = 1, enable = 0 WHERE name = 'alice'`)
	rep3, err := Run(k, data, opts(true, true))
	if err != nil {
		t.Fatal(err)
	}
	if rep3.UserSum.Update != 2 {
		t.Errorf("update: %+v", rep3.UserSum)
	}
	var en int
	_ = k.QueryRow(`SELECT traffic_limit, enable FROM users WHERE name = 'alice'`).Scan(&lim, &en)
	if lim != 20<<30 || en != 1 {
		t.Errorf("обновление не применилось: %d %d", lim, en)
	}
	_ = k.QueryRow(`SELECT COALESCE(SUM(used_traffic),0) FROM clients`).Scan(&used)
	if used != 3300 {
		t.Errorf("трафик изменился при обновлении: %d", used)
	}
	// Пользователи видны обычным API Kitsune и согласуются с SyncMembership.
	if err := db.SyncMembership(); err != nil {
		t.Fatal(err)
	}
	us, _ := db.GetUsers()
	if len(us) != 2 {
		t.Errorf("пользователей %d", len(us))
	}
}

func TestConflicts(t *testing.T) {
	k := openKitsune(t)
	mustExec(t, k, `INSERT INTO users (name, sub_id, uuid, password, ss_key) VALUES ('bob', 'other', 'ffffffff-ffff-4fff-8fff-ffffffffffff', 'p', 'k')`)
	mustExec(t, k, `INSERT INTO inbounds (tag, protocol, port, kind, settings) VALUES ('mine', 'vless', 443, 'vless-xhttp', '{}')`)
	data, _ := Read3XUI(xuiFixture(t))
	rep, err := Run(k, data, Options{Now: func() time.Time { return fixedNow }, PortReserved: func(p int, _ string) bool { return p == 2083 }})
	if err != nil {
		t.Fatal(err)
	}
	var bob *Item
	for i := range rep.Users {
		if rep.Users[i].Name == "bob_2" {
			bob = &rep.Users[i]
		}
	}
	if bob == nil || !bob.Conflict {
		t.Errorf("конфликт имени не найден: %+v", rep.Users)
	}
	if rep.InSum.Conflicts != 2 { // порт 443 занят другим типом, 2083 – панелью
		t.Errorf("конфликты подключений: %+v %+v", rep.InSum, rep.Inbounds)
	}
	if rep.InSum.Create != 1 {
		t.Errorf("создаваться должно только ws: %+v", rep.InSum)
	}
}

func TestMarzbanRunAndBatchDuplicate(t *testing.T) {
	k := openKitsune(t)
	data, _ := ReadMarzban(marzbanFixture(t))
	data.Users = append(data.Users, data.Users[0]) // дубль в источнике
	rep, err := Run(k, data, opts(true, false))
	if err != nil {
		t.Fatal(err)
	}
	if rep.UserSum.Create != 4 || rep.UserSum.Skip != 1 || rep.UserSum.Exists != 1 {
		t.Errorf("%+v %+v", rep.UserSum, rep.Users)
	}
	if len(rep.Notes) == 0 || !strings.Contains(strings.Join(rep.Notes, " "), "нет подключений") {
		t.Errorf("нет предупреждения про трафик без подключений: %v", rep.Notes)
	}
	// Повтор по Marzban (uuid у ivan, имена у остальных) не плодит дубли.
	data2, _ := ReadMarzban(marzbanFixture(t))
	if _, err := Run(k, data2, opts(true, false)); err != nil {
		t.Fatal(err)
	}
	if n := count(t, k, "users"); n != 4 {
		t.Errorf("после повтора пользователей %d", n)
	}
}

func TestRollbackOnError(t *testing.T) {
	k := openKitsune(t)
	// Триггер роняет вставку пользователя bob: всё, что было до неё, должно откатиться.
	mustExec(t, k, `CREATE TRIGGER fail_carol BEFORE INSERT ON users WHEN NEW.name = 'bob' BEGIN SELECT RAISE(ABORT, 'boom'); END`)
	data, _ := Read3XUI(xuiFixture(t))
	rep, err := Run(k, data, opts(true, false))
	if err == nil || rep != nil {
		t.Fatal("ждали ошибку")
	}
	if strings.Contains(err.Error(), "boom") {
		t.Errorf("текст ошибки базы утёк наружу: %v", err)
	}
	if count(t, k, "users") != 0 || count(t, k, "inbounds") != 0 || count(t, k, "clients") != 0 {
		t.Error("транзакция не откатилась")
	}
}

func TestLimitsOnRows(t *testing.T) {
	d, p := newFile(t)
	mustExec(t, d, `CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, status TEXT, used_traffic INT, data_limit INT, expire INT, note TEXT, on_hold_expire_duration INT)`)
	for i := 0; i < 3; i++ {
		mustExec(t, d, `INSERT INTO users (username) VALUES (?)`, fmt.Sprint("u", i))
	}
	got, err := selectRows(context.Background(), openForTest(t, p), "users", map[string]bool{"username": true}, []string{"username"}, "", 2)
	if err == nil || got != nil {
		t.Error("лимит строк не сработал")
	}
}

func openForTest(t *testing.T, p string) *sql.DB {
	d, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}
