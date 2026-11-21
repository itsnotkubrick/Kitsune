package importer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kitsune/internal/proto"
)

// Временная папка импорта лежит в текущем каталоге: тесты работают в своём временном.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "importer-test-")
	if err != nil {
		panic(err)
	}
	_ = os.Chdir(dir)
	code := m.Run()
	_ = os.Chdir(os.TempDir())
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func TestUUIDNormalized(t *testing.T) {
	canon := "11111111-2222-4333-8444-555555555555"
	forms := []string{
		"urn:uuid:" + canon,
		"{" + canon + "}",
		strings.ReplaceAll(canon, "-", ""),
		strings.ToUpper(canon),
		"  " + strings.ToUpper(canon) + " ",
	}
	for _, f := range forms {
		d, p := realXUI(t)
		addInbound(t, d, "r", 443, "vless", jsonOf(t, m{"clients": []m{{"id": f, "email": "u", "subId": "s1", "enable": true}}}), realityStream(t, "dest"))
		data, err := Read3XUI(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(data.Users) != 1 || data.Users[0].UUID != canon {
			t.Errorf("3x-ui %q: %+v", f, data.Users)
		}
	}
	// мусор не становится идентификатором
	d, p := realXUI(t)
	addInbound(t, d, "r", 443, "vless", jsonOf(t, m{"clients": []m{{"id": "not-a-uuid", "email": "u", "subId": "s1", "enable": true}}}), realityStream(t, "dest"))
	data, _ := Read3XUI(p)
	if data.Users[0].UUID != "" {
		t.Errorf("мусор: %q", data.Users[0].UUID)
	}
	// Marzban
	for _, f := range forms[:4] {
		d, p := newFile(t)
		mustExec(t, d, `CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, status TEXT, used_traffic INT, data_limit INT, expire INT, note TEXT, created_at TEXT, on_hold_expire_duration INT)`)
		mustExec(t, d, `CREATE TABLE proxies (id INTEGER PRIMARY KEY, user_id INT, type TEXT, settings TEXT)`)
		mustExec(t, d, `INSERT INTO users (id, username, status) VALUES (1, 'mz', 'active')`)
		mustExec(t, d, `INSERT INTO proxies (user_id, type, settings) VALUES (1, 'VLESS', ?)`, jsonOf(t, m{"id": f}))
		data, err := ReadMarzban(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(data.Users) != 1 || data.Users[0].UUID != canon {
			t.Errorf("marzban %q: %+v", f, data.Users)
		}
	}
}

func TestAccessWarning(t *testing.T) {
	k := openKitsune(t)
	data, _ := Read3XUI(xuiFixture(t))
	rep, err := Run(k, data, opts(false, false))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range rep.Warnings {
		found = found || w == AccessWarning
	}
	if !found {
		t.Errorf("нет предупреждения о доступе: %v", rep.Warnings)
	}
	rep, _ = Run(k, &Data{Source: Source3XUI}, opts(false, false))
	if len(rep.Warnings) != 0 {
		t.Errorf("предупреждение без пользователей: %v", rep.Warnings)
	}
}

func TestCheckTarget(t *testing.T) {
	cases := []struct {
		in, want string
		warn     bool
	}{
		{"www.example.com:443", "www.example.com:443", false},
		{"www.example.com", "www.example.com", false},
		{"www.example.com:0", "", true},
		{"www.example.com:65536", "", true},
		{"www.example.com:abc", "", true},
		{"www.example.com:1:2", "", true},
		{"127.0.0.1:2053", "", true},
		{"localhost:8443", "", true},
		{"[::1]:443", "", true},
		{"::1", "", true},
		{"10.1.2.3:443", "", true},
		{"192.168.0.5:443", "", true},
		{"172.16.0.1:443", "", true},
		{"0.0.0.0:80", "", true},
		{"8.8.8.8:443", "8.8.8.8:443", false},
	}
	for _, c := range cases {
		got, w := checkTarget(c.in)
		if got != c.want || (w != "") != c.warn {
			t.Errorf("%q: got %q warn %q", c.in, got, w)
		}
	}
	if _, w := checkTarget("127.0.0.1:2053"); w != localTargetWarn {
		t.Errorf("текст: %q", w)
	}
}

func TestRealityTargetAndPublicKey(t *testing.T) {
	priv, pub, _ := proto.RealityKeys()
	_, otherPub, _ := proto.RealityKeys()
	mk := func(target, pubKey string) string {
		return jsonOf(t, m{"network": "tcp", "security": "reality", "realitySettings": m{
			"target": target, "serverNames": []string{"www.example.com"}, "privateKey": priv, "shortIds": []string{"ab"},
			"settings": m{"publicKey": pubKey, "fingerprint": "chrome"}}})
	}
	d, p := realXUI(t)
	addInbound(t, d, "local", 443, "vless", `{"clients":[]}`, mk("127.0.0.1:2053", otherPub))
	addInbound(t, d, "badport", 444, "vless", `{"clients":[]}`, mk("www.example.com:99999", pub))
	data, err := Read3XUI(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range data.Inbounds {
		if in.Settings.Target != "" {
			t.Errorf("%s: target %q перенесён", in.Name, in.Settings.Target)
		}
		if in.Settings.PublicKey != pub {
			t.Errorf("%s: публичный ключ не вычислен из закрытого", in.Name)
		}
	}
	j := strings.Join(data.Inbounds[0].Warnings, "|")
	if !strings.Contains(j, "локальный адрес") || !strings.Contains(j, "не совпал") {
		t.Errorf("предупреждения local: %v", data.Inbounds[0].Warnings)
	}
	if !strings.Contains(strings.Join(data.Inbounds[1].Warnings, "|"), "неверным портом") {
		t.Errorf("предупреждения badport: %v", data.Inbounds[1].Warnings)
	}
}

func TestBigSettingsReported(t *testing.T) {
	d, p := realXUI(t)
	var sb strings.Builder
	sb.WriteString(`{"clients":[`)
	for i := 0; i < 5000; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`{"id":"11111111-2222-4333-8444-555555555555","email":"user` + strings.Repeat("x", 200) + `","enable":true}`)
	}
	sb.WriteString(`]}`)
	addInbound(t, d, "big", 443, "vless", sb.String(), realityStream(t, "dest"))
	data, err := Read3XUI(p)
	if err != nil {
		t.Fatal(err)
	}
	r := data.Inbounds[0].SkipReason
	if !strings.Contains(r, "настройки больше 1 МБ") || !strings.Contains(r, "5000") {
		t.Errorf("причина: %q", r)
	}
}

func TestReadBudgetAndValueLimit(t *testing.T) {
	d, p := realXUI(t)
	// значение больше предела длины: понятная ошибка, а не обрыв или память
	big := strings.Repeat("a", maxValueBytes+1024)
	mustExec(t, d, `INSERT INTO inbounds (remark, enable, port, protocol, settings, stream_settings, tag) VALUES ('x',1,443,'vless',?, '{}', 't')`, big)
	_, err := Read3XUI(p)
	if err == nil || !strings.Contains(err.Error(), "больше") {
		t.Errorf("ожидалась понятная ошибка: %v", err)
	}
	// сумма прочитанных байт
	d, p = realXUI(t)
	chunk := strings.Repeat("b", maxValueBytes/2)
	for i := 0; i < 10; i++ {
		mustExec(t, d, `INSERT INTO inbounds (remark, enable, port, protocol, settings, stream_settings, tag) VALUES ('x',1,?,'vless',?, '{}', ?)`, 1000+i, chunk, "t"+string(rune('a'+i)))
	}
	_, err = Read3XUI(p)
	if err == nil || !strings.Contains(err.Error(), "слишком большая") {
		t.Errorf("ожидалась ошибка бюджета: %v", err)
	}
}

func TestTempDirAndCleanup(t *testing.T) {
	t.Chdir(t.TempDir())
	root, err := TempRoot()
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(root); st.Mode().Perm() != 0o700 {
		t.Errorf("права: %v", st.Mode().Perm())
	}
	_ = os.Chmod(root, 0o755)
	_, _ = TempRoot()
	if st, _ := os.Stat(root); st.Mode().Perm() != 0o700 {
		t.Errorf("права не выправлены: %v", st.Mode().Perm())
	}
	for _, n := range []string{"kitsune-import-1", "kitsune-upload-2", "other"} {
		_ = os.MkdirAll(filepath.Join(root, n), 0o700)
	}
	CleanTempMinAge = 0
	CleanTemp()
	if _, err := os.Stat(filepath.Join(root, "kitsune-import-1")); err == nil {
		t.Error("остаток import не убран")
	}
	if _, err := os.Stat(filepath.Join(root, "kitsune-upload-2")); err == nil {
		t.Error("остаток upload не убран")
	}
	if _, err := os.Stat(filepath.Join(root, "other")); err != nil {
		t.Error("чужая папка удалена")
	}
}
