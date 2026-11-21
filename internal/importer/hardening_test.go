package importer

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// Вид, триггер и виртуальная таблица в чужой базе отклоняются сразу, до любых запросов.
func TestRejectsViewsTriggersVirtual(t *testing.T) {
	for name, q := range map[string]string{
		"view":    `CREATE VIEW v AS SELECT 1 AS x`,
		"trigger": `CREATE TRIGGER tr AFTER INSERT ON users BEGIN SELECT 1; END`,
		"virtual": `CREATE VIRTUAL TABLE vt USING fts5(a)`,
	} {
		d, p := newFile(t)
		mustExec(t, d, `CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, used_traffic INT, data_limit INT, expire INT)`)
		if _, err := d.Exec(q); err != nil {
			t.Logf("%s: сборка недоступна: %v", name, err)
			continue
		}
		if _, err := ReadMarzban(p); err == nil || !strings.Contains(err.Error(), "виды, триггеры") {
			t.Errorf("%s: база принята или неверная ошибка: %v", name, err)
		}
	}
}

// Запрос, который не заканчивается, обрывается по таймауту, а не держит блокировку.
func TestSelectRowsTimeout(t *testing.T) {
	d, p := newFile(t)
	mustExec(t, d, `CREATE VIEW inbounds AS WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT x AS id FROM c`)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := selectRows(ctx, openForTest(t, p), "inbounds", map[string]bool{"id": true}, []string{"id"}, "id", 10)
	if err == nil || !strings.Contains(err.Error(), "слишком много времени") {
		t.Errorf("ждали ошибку времени, получили %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("запрос не прерван: %v", time.Since(start))
	}
}

func TestFileErrorMessages(t *testing.T) {
	if _, err := Read3XUI(t.TempDir() + "/нет.db"); err == nil || !strings.Contains(err.Error(), "не найден") {
		t.Errorf("отсутствующий файл: %v", err)
	}
	_, p := realXUI(t)
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(p, 0o600)
	if f, err := os.Open(p); err == nil {
		f.Close()
		t.Skip("файл читается (root?)")
	}
	if _, err := Read3XUI(p); err == nil || !strings.Contains(err.Error(), "нет доступа") {
		t.Errorf("файл без прав: %v", err)
	}
}

func TestXUIInternalAndNodeInbounds(t *testing.T) {
	d, p := realXUI(t)
	mustExec(t, d, `ALTER TABLE inbounds ADD COLUMN node_id integer`)
	rs := realityStream(t, "target")
	addInbound(t, d, "pub", 443, "vless", `{"clients":[]}`, rs)
	mustExec(t, d, `INSERT INTO inbounds (remark, enable, port, protocol, settings, stream_settings, tag, listen) VALUES ('int',1,8443,'vless','{"clients":[]}',?, 't-int','127.0.0.1')`, rs)
	mustExec(t, d, `INSERT INTO inbounds (remark, enable, port, protocol, settings, stream_settings, tag, listen) VALUES ('any',1,9443,'vless','{"clients":[]}',?, 't-any','0.0.0.0')`, rs)
	mustExec(t, d, `INSERT INTO inbounds (remark, enable, port, protocol, settings, stream_settings, tag, node_id) VALUES ('node',1,10443,'vless','{"clients":[]}',?, 't-node', 3)`, rs)
	data, err := Read3XUI(p)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, in := range data.Inbounds {
		got[in.Name] = in.Kind != ""
	}
	if !got["pub"] || !got["any"] || got["int"] || got["node"] {
		t.Errorf("перенос подключений: %v", got)
	}
}

func TestDelayedStartTooLong(t *testing.T) {
	d, p := realXUI(t)
	addInbound(t, d, "r", 443, "vless", jsonOf(t, m{"clients": []m{
		{"id": uuidA, "email": "ok", "subId": "s1", "expiryTime": -86400000, "enable": true},
		{"id": uuidB, "email": "long", "subId": "s2", "expiryTime": -(maxDelayedMs + 1), "enable": true},
	}}), realityStream(t, "dest"))
	data, err := Read3XUI(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range data.Users {
		if u.Name == "ok" && (u.DelayedMs != 86400000 || u.ExpiryMs != 0) {
			t.Errorf("ok: %+v", u)
		}
		if u.Name == "long" && u.ExpiryMs != -1 {
			t.Errorf("long не отмечен как некорректный: %+v", u)
		}
	}
	k := openKitsune(t)
	rep, err := Run(k, data, opts(true, false))
	if err != nil {
		t.Fatal(err)
	}
	if rep.UserSum.Skip != 1 || rep.UserSum.Create != 1 {
		t.Errorf("итог: %+v", rep.UserSum)
	}
}

func TestTrojanPasswordKeptOnlyForTrojanNewSchema(t *testing.T) {
	d, p := newFile(t)
	mustExec(t, d, `CREATE TABLE inbounds (id INTEGER PRIMARY KEY, remark TEXT, enable NUMERIC, port INT, protocol TEXT, settings TEXT, stream_settings TEXT, tag TEXT)`)
	mustExec(t, d, `CREATE TABLE clients (id INTEGER PRIMARY KEY, email TEXT, sub_id TEXT, uuid TEXT, password TEXT, flow TEXT, limit_ip INT, total_gb INT, expiry_time INT, enable NUMERIC, comment TEXT)`)
	mustExec(t, d, `INSERT INTO inbounds (remark, enable, port, protocol, settings, stream_settings, tag) VALUES ('t',1,2083,'trojan',?, '{"network":"grpc","security":"tls"}','t')`,
		jsonOf(t, m{"clients": []m{{"email": "tr", "password": "trpass", "enable": true}}}))
	mustExec(t, d, `INSERT INTO clients (email, sub_id, uuid, password, enable) VALUES ('tr','s1','','trpass',1), ('ss','s2','','SSKEYAAAA==',1)`)
	data, err := Read3XUI(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range data.Users {
		if (u.Name == "tr") != (u.Password == "trpass") || (u.Name == "ss" && u.Password != "") {
			t.Errorf("%s: пароль %q", u.Name, u.Password)
		}
	}
}

func TestNameCollisionReported(t *testing.T) {
	d, p := newFile(t)
	mustExec(t, d, `CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, status TEXT, used_traffic INT, data_limit INT, expire INT, note TEXT, on_hold_expire_duration INT)`)
	for _, n := range []string{"a@x", "a@y", "a b"} {
		mustExec(t, d, `INSERT INTO users (username, status) VALUES (?, 'active')`, n)
	}
	data, _ := ReadMarzban(p)
	k := openKitsune(t)
	rep, err := Run(k, data, opts(true, false))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]Item{}
	for _, it := range rep.Users {
		names[it.Name] = it
	}
	if len(names) != 3 || names["a_2"].Action != ActCreate || !names["a_2"].Conflict || !strings.Contains(names["a_2"].Reason, "источника") {
		t.Errorf("отчёт: %+v", rep.Users)
	}
	// повторный прогон ничего не дублирует
	if rep, err = Run(k, data, opts(true, false)); err != nil || rep.UserSum.Create != 0 {
		t.Errorf("повторный прогон создал записи: %+v %v", rep.UserSum, err)
	}
}

// Срок отложенного старта не двигается при обновлении, а другие поля обновляются.
func TestUpdateKeepsDelayedExpiry(t *testing.T) {
	d, p := newFile(t)
	mustExec(t, d, `CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, status TEXT, used_traffic INT, data_limit INT, expire INT, note TEXT, on_hold_expire_duration INT)`)
	mustExec(t, d, `INSERT INTO users VALUES (1,'ivan','on_hold',0,1000,0,'n',86400)`)
	k := openKitsune(t)
	now := fixedNow
	o := Options{Apply: true, Update: true, Now: func() time.Time { return now }}
	data, _ := ReadMarzban(p)
	if _, err := Run(k, data, o); err != nil {
		t.Fatal(err)
	}
	mustExec(t, d, `UPDATE users SET data_limit = 2000, note = 'новая'`)
	data, _ = ReadMarzban(p)
	now = now.Add(72 * time.Hour)
	if _, err := Run(k, data, o); err != nil {
		t.Fatal(err)
	}
	var exp, lim int64
	var note string
	k.QueryRow(`SELECT expiry_time, traffic_limit, note FROM users WHERE name='ivan'`).Scan(&exp, &lim, &note)
	if want := fixedNow.UnixMilli() + 86400000; exp != want {
		t.Errorf("срок сдвинулся: %d, ждали %d", exp, want)
	}
	if lim != 2000 || note != "новая" {
		t.Errorf("остальное не обновилось: %d %q", lim, note)
	}
}

func TestReportLimit(t *testing.T) {
	r := &Report{UserSum: Counts{Create: 5, Skip: 1}}
	for i := 0; i < 5; i++ {
		r.Users = append(r.Users, Item{Name: "u", Action: ActCreate})
	}
	r.Users = append(r.Users, Item{Name: "bad", Action: ActSkip})
	r.Limit(3)
	if len(r.Users) != 3 || r.UsersMore != 3 || r.Users[0].Name != "bad" || r.UserSum.Create != 5 {
		t.Errorf("%+v", r)
	}
	r.Limit(10)
	if len(r.Users) != 3 || r.UsersMore != 3 {
		t.Errorf("повторный Limit: %+v", r)
	}
}
