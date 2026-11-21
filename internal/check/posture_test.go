package check

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"kitsune/internal/core"
	"kitsune/internal/db"
)

func TestPostureScore(t *testing.T) {
	if got := postureScore([]Item{{Level: OK}, {Level: Info}}); got != 100 {
		t.Errorf("чистый отчёт: %d", got)
	}
	if got := postureScore([]Item{{Level: Bad}, {Level: Warn}, {Level: Warn}}); got != 55 {
		t.Errorf("25+10+10: %d", got)
	}
	bad := make([]Item, 6)
	for i := range bad {
		bad[i].Level = Bad
	}
	if got := postureScore(bad); got != 0 {
		t.Errorf("оценка не уходит ниже нуля: %d", got)
	}
	if postureVerdict(95) == postureVerdict(30) {
		t.Error("вердикты должны различаться")
	}
}

func TestParseListen(t *testing.T) {
	cases := map[string]struct {
		port int
		ok   bool
	}{
		"   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1": {443, true},
		"   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1": {0, false}, // loopback
		"   3: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1": {0, false}, // 127.0.0.53 (локальный DNS systemd-resolved)
		"   4: 0100A8C0:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1": {53, true}, // 192.168.0.1: настоящий внешний адрес
		"   2: 00000000:0016 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 1 1": {0, false}, // не LISTEN
		"мусор": {0, false},
	}
	for line, want := range cases {
		p, ok := parseListen(line)
		if p != want.port || ok != want.ok {
			t.Errorf("%q: %d %v, ждали %d %v", line, p, ok, want.port, want.ok)
		}
	}
}

func TestLeakIn(t *testing.T) {
	if got := leakIn("Server: nginx\nX-Powered-By: Gin-Gonic and Kitsune"); len(got) != 2 {
		t.Errorf("%v", got)
	}
	if got := leakIn("<html>Welcome to nginx</html>"); len(got) != 0 {
		t.Errorf("ложное срабатывание: %v", got)
	}
}

func TestTLSLook(t *testing.T) {
	s := httptest.NewUnstartedServer(nil)
	s.TLS = &tls.Config{NextProtos: []string{"h2"}}
	s.EnableHTTP2 = true
	s.StartTLS()
	defer s.Close()
	_, p, _ := net.SplitHostPort(s.Listener.Addr().String())
	if _, err := strconv.Atoi(p); err != nil {
		t.Fatal(err)
	}
	st, err := tlsLook("127.0.0.1:"+p, "example.com", []string{"h2", "http/1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != tls.VersionTLS13 || st.NegotiatedProtocol != "h2" {
		t.Errorf("версия %x, протокол %q", st.Version, st.NegotiatedProtocol)
	}
	if _, err := tlsLook("127.0.0.1:1", "example.com", nil); err == nil {
		t.Error("закрытый порт должен давать ошибку")
	}
	if !strings.Contains(postureVerdict(100), "обычный") {
		t.Error("вердикт для чистого сервера")
	}
}

func TestPostureStepRegistered(t *testing.T) {
	found := false
	for _, s := range Steps() {
		if s.ID == "posture" && s.Group == postureGroup {
			found = true
		}
	}
	if !found {
		t.Fatal("шаг «Безопасность» не подключён к «Здоровью»")
	}
}

func TestPostureCoresOutdated(t *testing.T) {
	old := latestCores
	defer func() { latestCores = old }()
	latestCores = func(context.Context) []core.Latest {
		return []core.Latest{
			{ID: "xray", Pinned: "26.6.27", Verified: "26.6.27", Latest: "26.11.9", Newer: true},       // проверенная версия: оценка всё равно падает
			{ID: "singbox", Pinned: "1.13.0", Verified: "1.14.3", Latest: "1.15.0", Newer: true},       // устарело
			{ID: "mtg", Pinned: "2.2.8", Verified: "2.2.8", Latest: "2.3.0", Newer: true, Fresh: true}, // свежий выпуск: тоже считается
			{ID: "mita", Pinned: "3.38.1", Verified: "3.38.1", Latest: "3.38.1"},                       // актуально
		}
	}
	items := collect(checkPostureCores)
	// предупреждение об оценке и пояснение про Xray 26.9.8+ (у sing-box-клиентов REALITY не проходит)
	if len(items) != 2 || items[0].Level != Warn || items[1].Level != Info || !strings.Contains(items[1].Text, "X25519MLKEM768") {
		t.Fatalf("ждали предупреждение и пояснение: %+v", items)
	}
	text := items[0].Text
	for _, want := range []string{"Xray (стоит 26.6.27, вышла 26.11.9)", "sing-box (стоит 1.13.0, вышла 1.15.0)", "mtg (стоит 2.2.8, вышла 2.3.0, выпуск младше 3 суток)", "Оценка здоровья снижена на 10"} {
		if !strings.Contains(text, want) {
			t.Errorf("в тексте нет %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "mita") {
		t.Error("актуальное ядро не должно попасть в список")
	}
	if got := postureScore(items); got != 90 {
		t.Errorf("оценка должна снизиться ровно на 10 независимо от числа ядер: %d", got)
	}
	// всё актуально: строки нет
	latestCores = func(context.Context) []core.Latest {
		return []core.Latest{{ID: "xray", Pinned: "26.11.9", Latest: "26.11.9"}}
	}
	if got := collect(checkPostureCores); len(got) != 0 {
		t.Errorf("при актуальных версиях строки быть не должно: %+v", got)
	}
}

func TestPosture2FA(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	items := collect(checkPosture2FA)
	if len(items) != 1 || items[0].Level != Warn || !strings.Contains(items[0].Text, "двухфакторный вход") {
		t.Fatalf("без 2FA ждали предупреждение: %+v", items)
	}
	if got := postureScore(items); got != 90 {
		t.Errorf("отсутствие 2FA снижает оценку на 10: %d", got)
	}
	_ = db.SetSetting("totp_enabled", "1")
	if got := collect(checkPosture2FA); len(got) != 0 {
		t.Errorf("с 2FA строки быть не должно: %+v", got)
	}
}
