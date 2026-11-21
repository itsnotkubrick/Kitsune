package events

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kitsune/internal/db"
)

func setup(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	Init()
}

func TestAuditKeepsNewestFirst(t *testing.T) {
	setup(t)
	Audit("admin", "вход", "")
	Audit("admin", "создание пользователя", "alice")
	l := List(10)
	if len(l) != 2 || l[0].Action != "создание пользователя" || l[0].Detail != "alice" {
		t.Fatalf("журнал: %+v", l)
	}
}

func TestTelegramNotifyDedupAndFilter(t *testing.T) {
	setup(t)
	var mu = make(chan string, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		mu <- r.URL.Path + "|" + m["chat_id"].(string) + "|" + m["text"].(string)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	TelegramAPI = srv.URL
	_ = SaveTelegram(Telegram{Token: "123:ABC", ChatID: "42", Enabled: true, Events: []string{"core_down"}})

	Notify("core_down", "xray", "Xray остановлен", time.Hour)
	select {
	case got := <-mu:
		if !strings.HasPrefix(got, "/bot123:ABC/sendMessage|42|Kitsune: Xray остановлен") {
			t.Fatalf("запрос: %s", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("сообщение не отправлено")
	}
	Notify("core_down", "xray", "Xray остановлен", time.Hour) // дубль подавляется
	Notify("update", "v2", "Есть обновление", time.Hour)      // не выбранный вид события
	select {
	case got := <-mu:
		t.Fatalf("лишнее сообщение: %s", got)
	case <-time.After(500 * time.Millisecond):
	}
	if err := SendTest(); err != nil {
		t.Fatal(err)
	}
	<-mu
}

func TestTelegramErrorHidesToken(t *testing.T) {
	setup(t)
	TelegramAPI = "http://127.0.0.1:1"
	_ = SaveTelegram(Telegram{Token: "123:SECRET", ChatID: "1", Enabled: true})
	err := SendTest()
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("ошибка не должна содержать токен: %v", err)
	}
}
