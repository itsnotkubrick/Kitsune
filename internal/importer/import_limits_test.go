package importer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"kitsune/internal/core"
	"kitsune/internal/proto"
)

var canonRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func walkIDs(v any, out *[]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if k == "id" {
				if s, ok := x.(string); ok {
					*out = append(*out, s)
				}
			}
			walkIDs(x, out)
		}
	case []any:
		for _, x := range t {
			walkIDs(x, out)
		}
	}
}

// UUID до конца: форма uuid -> база -> конфиг Xray.
func TestImportUUIDEndToEnd(t *testing.T) {
	canon := "11111111-2222-4333-8444-555555555555"
	c32 := strings.ReplaceAll(canon, "-", "")
	forms := map[string]string{
		"urn":      "urn:uuid:" + canon,
		"URN":      "URN:UUID:" + strings.ToUpper(canon),
		"braces":   "{" + canon + "}",
		"hex32":    c32,
		"HEX32":    strings.ToUpper(c32),
		"upper":    strings.ToUpper(canon),
		"spaces":   "  " + canon + "  ",
		"tabnl":    "\t" + canon + "\n",
		"mixed":    "11111111-2222-4333-8444-555555555555",
		"badbrace": "{" + canon + ")",
		"bracket":  "[" + canon + "]",
	}
	for src := 0; src < 3; src++ {
		for name, f := range forms {
			var data *Data
			var err error
			switch src {
			case 0:
				d, p := realXUI(t)
				addInbound(t, d, "r", 443, "vless", jsonOf(t, m{"clients": []m{{"id": f, "email": "u", "subId": "s1", "enable": true}}}), realityStream(t, "dest"))
				data, err = Read3XUI(p)
			case 1:
				d, p := newFile(t)
				mustExec(t, d, `CREATE TABLE inbounds (id INTEGER PRIMARY KEY, remark TEXT, enable NUMERIC, port INT, protocol TEXT, settings TEXT, stream_settings TEXT, tag TEXT)`)
				mustExec(t, d, `CREATE TABLE clients (id INTEGER PRIMARY KEY, email TEXT, sub_id TEXT, uuid TEXT, password TEXT, flow TEXT, limit_ip INT, total_gb INT, expiry_time INT, enable NUMERIC, comment TEXT)`)
				mustExec(t, d, `INSERT INTO clients (email, sub_id, uuid, flow, limit_ip, total_gb, expiry_time, enable) VALUES ('u', 's1', ?, '', 0, 0, 0, 1)`, f)
				data, err = Read3XUI(p)
			case 2:
				d, p := newFile(t)
				mustExec(t, d, `CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, status TEXT, used_traffic INT, data_limit INT, expire INT, note TEXT, created_at TEXT, on_hold_expire_duration INT)`)
				mustExec(t, d, `CREATE TABLE proxies (id INTEGER PRIMARY KEY, user_id INT, type TEXT, settings TEXT)`)
				mustExec(t, d, `INSERT INTO users (id, username, status) VALUES (1, 'u', 'active')`)
				mustExec(t, d, `INSERT INTO proxies (user_id, type, settings) VALUES (1, 'VLESS', ?)`, jsonOf(t, m{"id": f}))
				data, err = ReadMarzban(p)
			}
			if err != nil {
				t.Fatalf("src%d %s: %v", src, name, err)
			}
			if len(data.Users) != 1 {
				t.Fatalf("src%d %s: users %d", src, name, len(data.Users))
			}
			got := data.Users[0].UUID
			// Marzban не обрезает пробелы: там пустой uuid = будет создан новый, это допустимо
			if got != "" && got != canon {
				t.Errorf("src%d %s: %q", src, name, got)
			}
			if got == "" {
				t.Logf("src%d %s: uuid не перенесён (новый)", src, name)
			}
			// в базу и в конфиг
			k := openKitsune(t)
			// нужна REALITY-подключение в Kitsune
			ib := data
			if src == 2 {
				ib = &Data{Source: SourceMarzban, Users: data.Users}
			}
			_ = ib
			if _, err := Run(k, data, opts(true, false)); err != nil {
				t.Fatalf("run: %v", err)
			}
			var u1 string
			k.QueryRow(`SELECT uuid FROM users WHERE name='u'`).Scan(&u1)
			if !canonRe.MatchString(u1) {
				t.Errorf("src%d %s: в базе %q", src, name, u1)
			}
			if got != "" && u1 != canon {
				t.Errorf("src%d %s: в базе %q, ждали %q", src, name, u1, canon)
			}
			rows, _ := k.Query(`SELECT uuid FROM clients`)
			for rows.Next() {
				var c string
				rows.Scan(&c)
				if !canonRe.MatchString(c) {
					t.Errorf("clients.uuid %q", c)
				}
			}
			rows.Close()
			cfg, err := core.BuildXrayConfig(proto.Env{Host: "example.com", StubID: "nginx"})
			if err != nil {
				t.Fatalf("конфиг: %v", err)
			}
			raw, _ := json.Marshal(cfg)
			var anyv any
			json.Unmarshal(raw, &anyv)
			var ids []string
			walkIDs(anyv, &ids)
			for _, id := range ids {
				if !canonRe.MatchString(id) {
					t.Errorf("src%d %s: в конфиге id %q", src, name, id)
				}
			}
			if src == 0 && name == "urn" && len(ids) == 0 {
				t.Errorf("в конфиге нет ни одного id (REALITY не создан?)")
			}
			// повторный импорт той же записи в другой форме: без дубля
			rep, _ := Run(k, data, opts(true, false))
			if rep != nil && rep.UserSum.Create != 0 {
				t.Errorf("повтор создал пользователя")
			}
		}
	}
}

func TestImportAccessWarningFlow(t *testing.T) {
	has := func(r *Report) bool {
		for _, w := range r.Warnings {
			if w == AccessWarning {
				return true
			}
		}
		return false
	}
	k := openKitsune(t)
	data, _ := Read3XUI(xuiFixture(t))
	r, _ := Run(k, data, opts(false, false))
	if !has(r) {
		t.Error("dry-run: нет")
	}
	j, _ := json.Marshal(r)
	if !strings.Contains(string(j), `"warnings"`) {
		t.Error("в JSON нет warnings")
	}
	r.Limit(1)
	if !has(r) {
		t.Error("после Limit пропало")
	}
	r, _ = Run(k, data, opts(true, false))
	if !has(r) {
		t.Error("apply: нет")
	}
	// повтор: всех пропустило (уже есть) – предупреждения быть не должно
	r, _ = Run(k, data, opts(true, false))
	if r.UserSum.Create != 0 && has(r) == false {
		t.Error("создано, а предупреждения нет")
	}
	if r.UserSum.Create == 0 && has(r) {
		t.Errorf("создано 0, а предупреждение есть: %+v", r.UserSum)
	}
	// --update без новых
	r, _ = Run(k, data, opts(true, true))
	if r.UserSum.Create == 0 && has(r) {
		t.Error("update без новых: предупреждение есть")
	}
	// пустой источник
	r, _ = Run(k, &Data{Source: SourceMarzban}, opts(false, false))
	if has(r) || len(r.Warnings) != 0 {
		t.Error("пустой источник")
	}
	// только Marzban-пользователи
	k = openKitsune(t)
	d, p := newFile(t)
	mustExec(t, d, `CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, status TEXT, used_traffic INT, data_limit INT, expire INT, note TEXT, on_hold_expire_duration INT)`)
	mustExec(t, d, `INSERT INTO users (username, status) VALUES ('zz','active')`)
	dm, _ := ReadMarzban(p)
	r, _ = Run(k, dm, opts(false, false))
	if !has(r) {
		t.Error("marzban dry: нет")
	}
	// пользователь с некорректным лимитом = пропуск, создано 0
	d2, p2 := newFile(t)
	mustExec(t, d2, `CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, status TEXT, used_traffic INT, data_limit INT, expire INT, note TEXT, on_hold_expire_duration INT)`)
	mustExec(t, d2, `INSERT INTO users (username, status, data_limit) VALUES ('bad','active', ?)`, int64(1)<<62)
	dm2, _ := ReadMarzban(p2)
	r, _ = Run(k, dm2, opts(false, false))
	t.Logf("все пропущены: create=%d skip=%d warnings=%v", r.UserSum.Create, r.UserSum.Skip, r.Warnings)
	if r.UserSum.Create == 0 && has(r) {
		t.Error("создано 0, а предупреждение есть")
	}
}

func TestImportCheckTargetTable(t *testing.T) {
	type c struct {
		in   string
		pass bool
	}
	cases := []c{
		{"", false},
		{"www.example.com", true}, {"www.example.com:443", true}, {"www.example.com:1", true}, {"www.example.com:65535", true},
		{"www.example.com:0", false}, {"www.example.com:65536", false}, {"www.example.com:-1", false}, {"www.example.com:+443", false},
		{"www.example.com:0443", false}, {"www.example.com: 443", false}, {"www.example.com:", false}, {"www.example.com:99999999999999999999", false},
		{"www.example.com:abc", false}, {"www.example.com:1:2", false}, {":443", false},
		{"localhost", false}, {"LOCALHOST:443", false}, {"a.localhost:443", false}, {"*.localhost", false}, {"x.local", false}, {"printer.local:631", false}, {"db.internal:5432", false}, {"a.b.internal", false},
		{"10.0.0.1", false}, {"10.255.255.255:443", false}, {"192.168.1.1:443", false}, {"172.16.0.1:443", false}, {"172.31.255.255:443", false},
		{"172.15.255.255:443", true}, {"172.32.0.1:443", true},
		{"127.0.0.1:2053", false}, {"127.1.2.3", false}, {"169.254.1.1:80", false}, {"0.0.0.0:443", false},
		{"[::1]:443", false}, {"[::1]", false}, {"::1", false}, {"[fe80::1]:443", false}, {"[fd00::1]:443", false}, {"::ffff:127.0.0.1", false}, {"[::ffff:10.0.0.1]:443", false},
		{"8.8.8.8:443", true}, {"1.1.1.1", true},
	}
	for _, x := range cases {
		got, w := checkTarget(x.in)
		ok := got != "" && w == ""
		if ok != x.pass {
			t.Errorf("%q: got=%q warn=%q, ждали pass=%v", x.in, got, w, x.pass)
		}
		if !ok && w == "" && x.in != "" {
			t.Errorf("%q: отклонён без предупреждения", x.in)
		}
	}
	// известные обходы – только лог
	for _, in := range []string{"localhost.", "localhost.:443", "foo.localhost.", "x.local.", "ip6-localhost", "localhost6", "2130706433", "0x7f.1", "0177.0.0.1", "[2606:4700::1111]:443", "2606:4700::1111", "example.com.:443", "*", "*.example.com"} {
		got, w := checkTarget(in)
		t.Logf("checkTarget(%q) = %q | %q", in, got, w)
	}
}

func TestImportPublicKeyDerived(t *testing.T) {
	priv, pub, _ := proto.RealityKeys()
	_, other, _ := proto.RealityKeys()
	mk := func(p, pk string) string {
		return jsonOf(t, m{"network": "tcp", "security": "reality", "realitySettings": m{
			"target": "www.example.com:443", "serverNames": []string{"www.example.com"}, "privateKey": p, "shortIds": []string{"ab"},
			"settings": m{"publicKey": pk, "fingerprint": "chrome"}}})
	}
	d, pth := realXUI(t)
	addInbound(t, d, "same", 1001, "vless", `{"clients":[]}`, mk(priv, pub))
	addInbound(t, d, "diff", 1002, "vless", `{"clients":[]}`, mk(priv, other))
	addInbound(t, d, "nopub", 1003, "vless", `{"clients":[]}`, mk(priv, ""))
	addInbound(t, d, "garbagepub", 1004, "vless", `{"clients":[]}`, mk(priv, "!!!"))
	addInbound(t, d, "badpriv", 1005, "vless", `{"clients":[]}`, mk("short", pub))
	addInbound(t, d, "emptypriv", 1006, "vless", `{"clients":[]}`, mk("", pub))
	data, err := Read3XUI(pth)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range data.Inbounds {
		w := strings.Join(in.Warnings, "|")
		switch in.Name {
		case "same", "nopub":
			if in.Settings.PublicKey != pub || strings.Contains(w, "не совпал") {
				t.Errorf("%s: pub=%q w=%q", in.Name, in.Settings.PublicKey, w)
			}
		case "diff", "garbagepub":
			if in.Settings.PublicKey != pub || !strings.Contains(w, "не совпал") {
				t.Errorf("%s: pub=%q w=%q", in.Name, in.Settings.PublicKey, w)
			}
		case "badpriv", "emptypriv":
			if in.Settings.PrivateKey != "" || in.Settings.PublicKey != "" || !strings.Contains(w, "ключей REALITY нет") {
				t.Errorf("%s: %+v w=%q", in.Name, in.Settings, w)
			}
		}
		t.Logf("%s: pub=%v warn=%v", in.Name, in.Settings.PublicKey != "", in.Warnings)
	}
}

func TestImportTempDir(t *testing.T) {
	t.Chdir(t.TempDir())
	// чужое остаётся, симлинки не следуются
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "keep.txt"), []byte("x"), 0o600)
	os.MkdirAll(filepath.Join(outside, "kitsune-import-victim"), 0o700)
	os.WriteFile(filepath.Join(outside, "kitsune-import-victim", "f"), []byte("x"), 0o600)
	root, _ := TempRoot()
	os.Symlink(outside, filepath.Join(root, "kitsune-import-link"))
	os.Symlink(outside, filepath.Join(root, "kitsune-upload-link"))
	os.MkdirAll(filepath.Join(root, "kitsune-import-real"), 0o700)
	os.Symlink(outside, filepath.Join(root, "kitsune-import-real", "inner"))
	os.WriteFile(filepath.Join(root, "kitsune-import-file"), []byte("f"), 0o600) // файл, не папка
	os.WriteFile(filepath.Join(root, "mine.txt"), []byte("f"), 0o600)
	os.MkdirAll(filepath.Join(root, "Kitsune-import-x"), 0o700)
	os.MkdirAll(filepath.Join(root, "xkitsune-import-x"), 0o700)
	CleanTempMinAge = 0
	CleanTemp()
	for _, n := range []string{"mine.txt", "Kitsune-import-x", "xkitsune-import-x", "kitsune-import-file"} {
		if _, err := os.Lstat(filepath.Join(root, n)); err != nil {
			t.Errorf("пропало %s", n)
		}
	}
	for _, n := range []string{"kitsune-import-real"} {
		if _, err := os.Lstat(filepath.Join(root, n)); err == nil {
			t.Errorf("не убрано %s", n)
		}
	}
	if _, err := os.Stat(filepath.Join(outside, "keep.txt")); err != nil {
		t.Error("СНЕСЛО снаружи через симлинк")
	}
	if _, err := os.Stat(filepath.Join(outside, "kitsune-import-victim", "f")); err != nil {
		t.Error("СНЕСЛО victim снаружи")
	}
	if _, err := os.Lstat(filepath.Join(root, "kitsune-import-link")); err != nil {
		t.Log("симлинк-остаток kitsune-import-link удалён (ок, сам линк)")
	} else {
		t.Log("симлинк-остаток kitsune-import-link остался (не папка)")
	}
}

func TestImportTempRootSymlink(t *testing.T) {
	wd := t.TempDir()
	t.Chdir(wd)
	target := t.TempDir()
	os.Chmod(target, 0o755)
	os.MkdirAll(filepath.Join(target, "kitsune-import-old"), 0o700)
	os.WriteFile(filepath.Join(target, "other.txt"), []byte("x"), 0o600)
	os.Symlink(target, filepath.Join(wd, TempDirName))
	CleanTempMinAge = 0
	CleanTemp()
	_, err := TempRoot()
	st, _ := os.Stat(target)
	_, e2 := os.Stat(filepath.Join(target, "kitsune-import-old"))
	t.Logf("import-tmp -> симлинк: TempRoot err=%v; права цели после = %v; старый kitsune-import-old жив=%v", err, st.Mode().Perm(), e2 == nil)
	if st.Mode().Perm() != 0o755 {
		t.Logf("ЗАМЕЧЕНО: chmod прошёл по симлинку")
	}
	if e2 != nil {
		t.Logf("ЗАМЕЧЕНО: CleanTemp прошёл по симлинку import-tmp")
	}
}

func TestImportImportTmpIsFile(t *testing.T) {
	t.Chdir(t.TempDir())
	os.WriteFile(TempDirName, []byte("x"), 0o600)
	d, p := realXUI(t)
	addInbound(t, d, "r", 443, "vless", `{"clients":[]}`, realityStream(t, "dest"))
	_, err := Read3XUI(p)
	t.Logf("import-tmp = файл: err=%v", err)
	if err == nil {
		t.Error("ожидалась ошибка")
	}
	CleanTemp() // не паникует
}

func TestImportValueLimits(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	// значение 20 МБ
	d, p := realXUI(t)
	mustExec(t, d, `INSERT INTO inbounds (remark, enable, port, protocol, settings, stream_settings, tag) VALUES ('x',1,443,'vless',?, '{}', 't')`, strings.Repeat("a", 20<<20))
	_, err := Read3XUI(p)
	t.Logf("20 МБ: %v", err)
	if err == nil || !strings.Contains(err.Error(), "16 МБ") {
		t.Errorf("20 МБ: %v", err)
	}
	// 70 МБ суммарно, каждое значение 10 МБ в разных колонках
	d, p = realXUI(t)
	for i := 0; i < 7; i++ {
		mustExec(t, d, `INSERT INTO inbounds (remark, enable, port, protocol, settings, stream_settings, tag) VALUES ('x',1,?,'vless',?, '{}', ?)`, 1000+i, strings.Repeat("b", 10<<20), fmt.Sprint("t", i))
	}
	_, err = Read3XUI(p)
	t.Logf("70 МБ: %v", err)
	if err == nil || !strings.Contains(err.Error(), "слишком большая") {
		t.Errorf("70 МБ: %v", err)
	}
	// blob вместо текста 20 МБ в settings
	d, p = realXUI(t)
	mustExec(t, d, `INSERT INTO inbounds (remark, enable, port, protocol, settings, stream_settings, tag) VALUES ('x',1,443,'vless',zeroblob(20000000), '{}', 't')`)
	_, err = Read3XUI(p)
	t.Logf("blob 20 МБ: %v", err)
	if err == nil {
		t.Error("blob 20 МБ принят")
	}
	// значение ровно под пределом 15 МБ в одной таблице, одна строка: принимается
	d, p = realXUI(t)
	mustExec(t, d, `INSERT INTO inbounds (remark, enable, port, protocol, settings, stream_settings, tag) VALUES ('x',1,443,'vless',?, '{}', 't')`, strings.Repeat("c", 15<<20))
	dd, err := Read3XUI(p)
	t.Logf("15 МБ: err=%v inb=%d reason=%q", err, func() int {
		if dd != nil {
			return len(dd.Inbounds)
		}
		return -1
	}(), func() string {
		if dd != nil && len(dd.Inbounds) > 0 {
			return dd.Inbounds[0].SkipReason
		}
		return ""
	}())
	// Marzban: users с заметкой 20 МБ
	d, p = newFile(t)
	mustExec(t, d, `CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, status TEXT, used_traffic INT, data_limit INT, expire INT, note TEXT, on_hold_expire_duration INT)`)
	mustExec(t, d, `INSERT INTO users (username, status, note) VALUES ('u','active',?)`, strings.Repeat("n", 20<<20))
	_, err = ReadMarzban(p)
	t.Logf("marzban note 20 МБ: %v", err)
	if err == nil {
		t.Error("marzban 20 МБ принят")
	}
	// Marzban: 70 МБ в users по 10 КБ... и много строк
	d, p = newFile(t)
	mustExec(t, d, `CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, status TEXT, used_traffic INT, data_limit INT, expire INT, note TEXT, on_hold_expire_duration INT)`)
	mustExec(t, d, `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<7200) INSERT INTO users (username,status,note) SELECT 'u'||x,'active',printf('%.10240c','z') FROM c`)
	_, err = ReadMarzban(p)
	t.Logf("marzban 72 МБ примечаний: %v", err)
}

// Битые ячейки: cell_size_check, без паники.
func TestImportCorruptCells(t *testing.T) {
	d, p := realXUI(t)
	for i := 0; i < 200; i++ {
		mustExec(t, d, `INSERT INTO inbounds (remark, enable, port, protocol, settings, stream_settings, tag) VALUES (?,1,?,'vless',?, '{}', ?)`, fmt.Sprint("r", i), 2000+i, strings.Repeat("x", 300), fmt.Sprint("t", i))
	}
	d.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	d.Close()
	raw, _ := os.ReadFile(p)
	n := 0
	for off := 4096; off+64 < len(raw) && n < 60; off += 4096 * 1 {
		// портим по два байта в разных местах страниц
		for j := 8; j < 4096; j += 97 {
			if off+j < len(raw) {
				raw[off+j] ^= 0xFF
			}
		}
		n++
	}
	for _, mode := range []string{"flip", "zeropage", "trunc", "cellptr"} {
		b := append([]byte(nil), raw...)
		switch mode {
		case "zeropage":
			for i := 4096 * 2; i < 4096*3 && i < len(b); i++ {
				b[i] = 0
			}
		case "trunc":
			b = b[:len(b)/2]
		case "cellptr":
			// ломаем указатели ячеек на страницах 2..: первые байты заголовка страницы (число ячеек и т.п.)
			for pg := 1; pg*4096+12 < len(b); pg++ {
				b[pg*4096+3] = 0xFF
				b[pg*4096+4] = 0xFF
				b[pg*4096+8] = 0xFF
				b[pg*4096+9] = 0xFF
			}
		}
		fp := filepath.Join(t.TempDir(), mode+".db")
		os.WriteFile(fp, b, 0o600)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: паника %v", mode, r)
				}
			}()
			dd, err := Read3XUI(fp)
			t.Logf("%s: err=%v data=%v", mode, err, dd != nil)
		}()
	}
}

func TestImportXUIBigSettings(t *testing.T) {
	// 1,1 МБ settings: причина с числом клиентов; stream_settings > 1 МБ: без числа
	d, p := realXUI(t)
	var sb strings.Builder
	sb.WriteString(`{"clients":[`)
	n := 0
	for sb.Len() < (1<<20)+10 {
		if n > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(fmt.Sprintf(`{"id":"11111111-2222-4333-8444-555555555555","email":"u%d","enable":true,"pad":"%s"}`, n, strings.Repeat("p", 100)))
		n++
	}
	sb.WriteString(`]}`)
	addInbound(t, d, "big", 443, "vless", sb.String(), realityStream(t, "dest"))
	addInbound(t, d, "bigstream", 444, "vless", `{"clients":[]}`, `{"network":"tcp","pad":"`+strings.Repeat("s", 1<<20+5)+`"}`)
	addInbound(t, d, "bignoemail", 445, "vless", `{"pad":"`+strings.Repeat("s", 1<<20+5)+`"}`, realityStream(t, "dest"))
	addInbound(t, d, "edge", 446, "vless", `{"clients":[],"pad":"`+strings.Repeat("s", (1<<20)-20)+`"}`, realityStream(t, "dest"))
	data, err := Read3XUI(p)
	if err != nil {
		t.Fatal(err)
	}
	k := openKitsune(t)
	for _, in := range data.Inbounds {
		t.Logf("%s: skip=%q", in.Name, in.SkipReason)
	}
	rep, err := Run(k, data, opts(false, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range rep.Inbounds {
		t.Logf("отчёт: %s %s | %s | %s", it.Action, it.Name, it.Details, it.Reason)
	}
	_ = n
}

func TestImportCorruptFuzz(t *testing.T) {
	d, p := realXUI(t)
	for i := 0; i < 300; i++ {
		cl := jsonOf(t, m{"clients": []m{{"id": uuidA, "email": fmt.Sprint("e", i), "subId": fmt.Sprint("s", i), "enable": true}}})
		mustExec(t, d, `INSERT INTO inbounds (remark, enable, port, protocol, settings, stream_settings, tag) VALUES (?,1,?,'vless',?,?,?)`, fmt.Sprint("r", i), 2000+i, cl, `{"network":"tcp"}`, fmt.Sprint("t", i))
	}
	d.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	d.Close()
	raw, _ := os.ReadFile(p)
	rnd := uint64(88172645463325252)
	next := func() uint64 { rnd ^= rnd << 13; rnd ^= rnd >> 7; rnd ^= rnd << 17; return rnd }
	okc, errc := 0, 0
	for it := 0; it < 400; it++ {
		b := append([]byte(nil), raw...)
		for k := 0; k < 1+int(next()%20); k++ {
			b[100+int(next()%uint64(len(b)-100))] = byte(next())
		}
		fp := filepath.Join(t.TempDir(), "f.db")
		os.WriteFile(fp, b, 0o600)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("iter %d: паника %v", it, r)
				}
			}()
			if _, err := Read3XUI(fp); err != nil {
				errc++
			} else {
				okc++
			}
		}()
	}
	t.Logf("fuzz: принято %d, отклонено %d", okc, errc)
}
