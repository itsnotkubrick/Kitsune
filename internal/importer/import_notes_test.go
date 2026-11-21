package importer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// config.json с комментариями, BOM и запятыми в конце читается; текст в кавычках не портится.
func TestReadXrayConfigCommentsBOMAndCommas(t *testing.T) {
	body := "\xef\xbb\xbf// заголовок\n{\n  /* блок */\n  \"inbounds\": [\n    {\"tag\": \"T // не комментарий, /* и это тоже */\", \"port\": 8081, \"protocol\": \"trojan\",\n     \"settings\": {\"clients\": [],}, // хвост\n    },\n  ],\n}\n"
	d, err := ReadXrayConfig(writeTemp(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Inbounds) != 1 || !strings.Contains(d.Inbounds[0].Name, "// не комментарий") {
		t.Fatalf("%+v", d.Inbounds)
	}
}

func TestReadXrayConfigMessages(t *testing.T) {
	for body, want := range map[string]string{
		"":                     "пустой",
		"  \n":                 "пустой",
		"{oops":                "не JSON",
		`{"inbounds":{}}`:      "неверной формы",
		`[1,"a"]`:              "неверной формы",
		`{"inbounds":[1,"a"]}`: "неверной формы",
		`{"inbounds":[]}`:      "нет подключений",
		`{"a": /* не закрыт }`: "не JSON",
	} {
		_, err := ReadXrayConfig(writeTemp(t, body))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: ждали «%s», получили %v", body, want, err)
		}
	}
}

func TestMarzbanAPIRedirectMessage(t *testing.T) {
	for _, code := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://other.invalid/", code)
		}))
		_, err := ReadMarzbanAPI(context.Background(), srv.URL, APIAuth{Token: "t"})
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "перенаправляет") || strings.Contains(err.Error(), "ошибкой") {
			t.Errorf("%d: %v", code, err)
		}
	}
}

func TestMarzbanTrojanBadPasswordWarns(t *testing.T) {
	u, ok := marzbanUser(map[string]any{"username": "bob"}, []marzbanProxy{{password: "has space"}})
	if !ok || u.Password != "" || len(u.Warnings) != 1 || strings.Contains(u.Warnings[0], "has space") {
		t.Fatalf("%+v", u)
	}
}

// Ограничения скорости и таймеры, которые нельзя перенести, дают предупреждение, а «1 gbps» переводится в мегабиты.
func TestQUICLimitsAndTimersWarn(t *testing.T) {
	stream := map[string]any{"finalmask": map[string]any{"quicParams": map[string]any{"brutalUp": "1 gbps", "brutalDown": "100 kbps"}}}
	_, s, _, w := mapHysteria2(stream)
	if s.UpMbps != "1000" || s.DownMbps != "" || !hasWarn(w, "загрузки") || hasWarn(w, "отдачи") {
		t.Errorf("up=%q down=%q w=%v", s.UpMbps, s.DownMbps, w)
	}
	_, s, _, w = mapHysteria2(map[string]any{"finalmask": map[string]any{"quicParams": map[string]any{"brutalUp": float64(0), "brutalDown": ""}}})
	if s.UpMbps != "" || hasWarn(w, "скорости") {
		t.Errorf("0 и пусто – не ошибка: %v", w)
	}
	_, s, _, w = mapTUIC(map[string]any{"heartbeat": "10", "auth_timeout": "3s"}, nil)
	if s.Heartbeat != "" || s.AuthTimeout != "3s" || !hasWarn(w, "heartbeat") || hasWarn(w, "auth_timeout") {
		t.Errorf("hb=%q at=%q w=%v", s.Heartbeat, s.AuthTimeout, w)
	}
}

// Отменённый контекст прекращает чтение API, запрос не уходит на сервер.
func TestMarzbanAPICancelledContext(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadMarzbanAPI(ctx, srv.URL, APIAuth{Token: "t"}); err == nil || hits != 0 {
		t.Errorf("err=%v hits=%d", err, hits)
	}
}
