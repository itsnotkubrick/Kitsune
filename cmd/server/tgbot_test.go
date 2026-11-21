package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
	"kitsune/internal/events"
)

func TestBotBackendUserLifecycle(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	b := botBackend{}

	u, err := b.Create("Alice Smith", 30, 5)
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "Alice_Smith" || u.Limit != 5<<30 || !u.Enabled || !u.Active {
		t.Fatalf("создан: %+v", u)
	}
	if left := time.Until(time.UnixMilli(u.ExpiryMs)); left < 29*24*time.Hour || left > 31*24*time.Hour {
		t.Errorf("срок должен быть около 30 дней: %v", left)
	}
	if _, err := b.Create("alice smith", 0, 0); err == nil {
		t.Error("повторное имя (в другом написании) принято")
	}
	if _, err := b.Create("!!!", 0, 0); err == nil {
		t.Error("имя без букв и цифр принято")
	}
	for _, name := range []string{"Alice_Smith", "alice_smith", "Alice Smith", "ALICE SMITH"} {
		if f, ok := b.Find(name); !ok || f.ID != u.ID {
			t.Errorf("не нашёл %q", name)
		}
	}
	if _, ok := b.Find("nobody"); ok {
		t.Error("нашёл несуществующего")
	}

	// продление прибавляется к действующему сроку
	nu, err := b.Extend(u.ID, 10)
	if err != nil || nu.ExpiryMs != u.ExpiryMs+10*24*3600*1000 {
		t.Errorf("продление: %+v %v (было %d)", nu, err, u.ExpiryMs)
	}
	// истёкший срок считается от сегодня
	past := time.Now().Add(-48 * time.Hour).UnixMilli()
	_ = db.UpdateUser(u.ID, db.UserPatch{ExpiryTime: &past})
	nu, _ = b.Extend(u.ID, 7)
	if left := time.Until(time.UnixMilli(nu.ExpiryMs)); left < 6*24*time.Hour || left > 8*24*time.Hour {
		t.Errorf("после истёкшего срока +7 дней должно быть около недели: %v", left)
	}

	off, err := b.SetEnabled(u.ID, false)
	if err != nil || off.Enabled || off.Active {
		t.Errorf("пауза: %+v %v", off, err)
	}
	on, _ := b.SetEnabled(u.ID, true)
	if !on.Enabled {
		t.Error("включение не сработало")
	}
	if _, err := b.SetEnabled(99999, true); err == nil {
		t.Error("несуществующий пользователь изменён")
	}

	// ссылка: без запомненного адреса – понятная просьба, с адресом – ссылка подписки
	if _, err := b.Link(u.ID); err == nil || !strings.Contains(err.Error(), "адрес панели") {
		t.Errorf("без адреса: %v", err)
	}
	_ = db.SetSetting("sub_base", "https://panel.example.org:8443/")
	link, err := b.Link(u.ID)
	full, _ := db.GetUser(u.ID)
	if err != nil || link != "https://panel.example.org:8443/sub/"+full.SubID {
		t.Errorf("ссылка: %q %v", link, err)
	}
	if st := b.Status(); !strings.Contains(st, "Пользователей: активных 1 из 1") {
		t.Errorf("статус: %s", st)
	}
}

func tgSettingsReq(t *testing.T, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.PUT("/t", handleTelegramSet)
	r.GET("/t", handleTelegramGet)
	req := httptest.NewRequest(method, "/t", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestTelegramBotSettingsValidation(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	events.Init()

	// бот без администраторов или без токена не включается
	if rec := tgSettingsReq(t, "PUT", `{"token":"123:abc","bot":true,"admins":[]}`); rec.Code != http.StatusBadRequest {
		t.Errorf("бот без администраторов: %d %s", rec.Code, rec.Body.String())
	}
	if rec := tgSettingsReq(t, "PUT", `{"bot":true,"admins":[5]}`); rec.Code != http.StatusBadRequest {
		t.Errorf("бот без токена: %d", rec.Code)
	}
	for _, bad := range []string{`[0]`, `[-5]`, `[1,2,3,4,5,6,7,8,9,10,11]`} {
		if rec := tgSettingsReq(t, "PUT", `{"token":"123:abc","bot":true,"admins":`+bad+`}`); rec.Code != http.StatusBadRequest {
			t.Errorf("администраторы %s приняты: %d", bad, rec.Code)
		}
	}
	// верные настройки сохраняются, повторы убираются; уведомления при этом не обязаны быть включены
	if rec := tgSettingsReq(t, "PUT", `{"token":"123:abc","bot":true,"admins":[42,42,7]}`); rec.Code != http.StatusOK {
		t.Fatalf("верные настройки: %d %s", rec.Code, rec.Body.String())
	}
	tg := events.LoadTelegram()
	if !tg.Bot || len(tg.Admins) != 2 || tg.Admins[0] != 42 || tg.Admins[1] != 7 || tg.Enabled {
		t.Errorf("сохранено: %+v", tg)
	}
	rec := tgSettingsReq(t, "GET", "")
	if !strings.Contains(rec.Body.String(), `"bot":true`) || !strings.Contains(rec.Body.String(), `"admins":[42,7]`) || strings.Contains(rec.Body.String(), "123:abc") {
		t.Errorf("GET: %s (токен отдавать нельзя)", rec.Body.String())
	}
	// выключить бота можно без ограничений
	if rec := tgSettingsReq(t, "PUT", `{"bot":false,"admins":[]}`); rec.Code != http.StatusOK {
		t.Errorf("выключение: %d %s", rec.Code, rec.Body.String())
	}
}

// Адрес для ссылок бота запоминается, когда администратор открывает панель по настоящему имени, и не запоминается для локального (SSH-туннель).
func TestRememberSubBase(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	call := func(host string) {
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.GET("/x", func(c *gin.Context) { rememberSubBase(c) })
		req := httptest.NewRequest("GET", "/x", nil)
		req.Host = host
		r.ServeHTTP(httptest.NewRecorder(), req)
	}
	call("127.0.0.1:8080")
	call("localhost:8080")
	if v := db.GetSetting("sub_base", ""); v != "" {
		t.Fatalf("локальный адрес запомнен: %q", v)
	}
	call("evil host/x:80") // служебные символы в Host
	if v := db.GetSetting("sub_base", ""); v != "" {
		t.Fatalf("мусорный Host запомнен: %q", v)
	}
	call("panel.example.org:8443")
	if v := db.GetSetting("sub_base", ""); v != "http://panel.example.org:8443" {
		t.Fatalf("адрес панели: %q", v)
	}
	if got := botSubBase(); got != "http://panel.example.org:8443" {
		t.Errorf("botSubBase: %q", got)
	}
	// без запомненного адреса берётся адрес сервера и порт панели
	_ = db.SetSetting("sub_base", "")
	_ = db.SetSetting("public_host", "203.0.113.5")
	if got := botSubBase(); got != "http://203.0.113.5:8080" {
		t.Errorf("запасной адрес: %q", got)
	}
}

func TestBotBackendDelete(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	b := botBackend{}
	u, err := b.Create("victim", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	keep, _ := b.Create("keeper", 0, 0)
	if err := b.Delete(u.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Find("victim"); ok {
		t.Error("пользователь остался")
	}
	if _, ok := b.Find("keeper"); !ok || keep.ID == u.ID {
		t.Error("удалён не тот пользователь")
	}
	if err := b.Delete(u.ID); err == nil {
		t.Error("повторное удаление не вернуло ошибку")
	}
}
