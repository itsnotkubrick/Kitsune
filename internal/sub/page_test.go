package sub

import (
	"strings"
	"testing"
	"time"

	"kitsune/internal/db"
)

func TestWantsPage(t *testing.T) {
	br := "Mozilla/5.0 (iPhone) Safari"
	if !WantsPage("text/html,application/xhtml+xml", br, "", "") {
		t.Fatal("браузер должен получить страницу")
	}
	if WantsPage("*/*", "Happ/1.9", "", "") || WantsPage("text/html", "Hiddify/2.0", "", "") {
		t.Fatal("приложения получают подписку, а не страницу")
	}
	if WantsPage("text/html", br, "raw", "") {
		t.Fatal("явный format отключает страницу")
	}
	if !WantsPage("*/*", "curl/8", "", "1") {
		t.Fatal("?page=1 включает страницу")
	}
}

func TestPageContent(t *testing.T) {
	u := db.User{Name: "Маша <b>", Enable: true, TrafficLimit: 10 << 30, UsedTraffic: 5 << 30, IPLimit: 3}
	out := string(Page(u, "https://x.example/sub/abc"))
	for _, want := range []string{"Активна", "5.0 ГБ из 10.0 ГБ", "до 3", "happ://add/https://x.example/sub/abc", "data:image/png;base64,", "width:50%"} {
		if !strings.Contains(out, want) {
			t.Errorf("в странице нет %q", want)
		}
	}
	if strings.Contains(out, "Маша <b>") {
		t.Error("имя пользователя не экранировано")
	}
}

func TestPercentUsed(t *testing.T) {
	cases := []struct {
		used, limit int64
		want        int
	}{
		{0, 100, 0}, {50, 100, 50}, {-50, 100, 0}, {200, 100, 100},
		{1 << 62, 1<<63 - 1, 50}, {1 << 62, 0, 0},
	}
	for _, c := range cases {
		if got := percentUsed(c.used, c.limit); got != c.want {
			t.Errorf("percentUsed(%d,%d) = %d, ждали %d", c.used, c.limit, got, c.want)
		}
	}
}

func TestExpiryText(t *testing.T) {
	now := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	ms := func(d time.Duration) int64 { return now.Add(d).UnixMilli() }
	cases := []struct {
		in   int64
		want string
	}{
		{0, "бессрочно"}, {-86400000, "бессрочно"}, {ms(-time.Hour), "истёк"},
		{ms(49 * time.Hour), "ещё 2 дн."}, {ms(5*time.Hour + 10*time.Minute), "ещё 5 ч."}, {ms(20 * time.Minute), "меньше часа"},
	}
	for _, c := range cases {
		if got := expiryText(c.in, now); !strings.Contains(got, c.want) {
			t.Errorf("expiryText(%d) = %q, ждали %q", c.in, got, c.want)
		}
	}
}

func TestPageNoLimitWording(t *testing.T) {
	out := string(Page(db.User{Name: "a", Enable: true}, "https://x.example/sub/abc"))
	if !strings.Contains(out, "0 Б, без ограничений") || strings.Contains(out, "из без") {
		t.Error("неверная формулировка безлимитного трафика")
	}
}
