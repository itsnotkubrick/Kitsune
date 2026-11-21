package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
)

func bulkCall(t *testing.T, body string) (int, map[string]any) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/users/bulk", handleBulkUsers)
	req := httptest.NewRequest(http.MethodPost, "/users/bulk", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func mustUser(t *testing.T, name string, expiry int64) *db.User {
	t.Helper()
	u, err := db.CreateUser(name, 0, expiry, 0)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestBulkUsers(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	applies := 0
	old := bulkApply
	bulkApply = func() error { applies++; return nil }
	defer func() { bulkApply = old }()

	day := int64(24 * time.Hour / time.Millisecond)
	soon := time.Now().UnixMilli() + 2*day
	a := mustUser(t, "a", soon)
	b := mustUser(t, "b", 0)                          // бессрочный
	c := mustUser(t, "c", time.Now().UnixMilli()-day) // срок вышел

	// отключение: дубли в списке считаются один раз, повтор ничего не меняет
	code, out := bulkCall(t, `{"ids":[`+itoa(a.ID)+`,`+itoa(a.ID)+`,`+itoa(b.ID)+`],"action":"disable"}`)
	if code != 200 || out["done"].(float64) != 2 {
		t.Fatalf("disable: %d %v", code, out)
	}
	code, out = bulkCall(t, `{"ids":[`+itoa(a.ID)+`],"action":"disable"}`)
	if code != 200 || out["done"].(float64) != 0 || out["skipped"].(float64) != 1 {
		t.Fatalf("повторное отключение: %d %v", code, out)
	}
	if u, _ := db.GetUser(a.ID); u.Enable {
		t.Error("пользователь a остался включённым")
	}

	// продление: бессрочный пропускается, истёкший считается от сегодняшнего дня
	code, out = bulkCall(t, `{"ids":[`+itoa(a.ID)+`,`+itoa(b.ID)+`,`+itoa(c.ID)+`],"action":"extend","days":30}`)
	if code != 200 || out["done"].(float64) != 2 || out["skipped"].(float64) != 1 {
		t.Fatalf("extend: %d %v", code, out)
	}
	ua, _ := db.GetUser(a.ID)
	if want := soon + 30*day; ua.ExpiryTime != want {
		t.Errorf("a: срок %d, ожидался %d", ua.ExpiryTime, want)
	}
	uc, _ := db.GetUser(c.ID)
	if min, max := time.Now().UnixMilli()+29*day, time.Now().UnixMilli()+31*day; uc.ExpiryTime < min || uc.ExpiryTime > max {
		t.Errorf("c: срок %d вне %d..%d", uc.ExpiryTime, min, max)
	}
	if ub, _ := db.GetUser(b.ID); ub.ExpiryTime != 0 {
		t.Error("бессрочный получил срок")
	}

	// неверный ввод
	for _, bad := range []string{
		`{"ids":[],"action":"delete"}`,
		`{"ids":[1],"action":"explode"}`,
		`{"ids":[1],"action":"extend","days":0}`,
		`{"ids":[1],"action":"extend","days":99999}`,
		`not json`,
	} {
		if code, _ := bulkCall(t, bad); code != 400 {
			t.Errorf("%s: код %d, ожидался 400", bad, code)
		}
	}

	if applies != 2 { // отключение и продление; повторное отключение ничего не меняло и ядра не трогает
		t.Errorf("ядра пересобраны %d раз", applies)
	}

	// удаление; несуществующий id считается неудачей, остальные обрабатываются
	code, out = bulkCall(t, `{"ids":[`+itoa(a.ID)+`,`+itoa(b.ID)+`,9999],"action":"delete"}`)
	if code != 200 || out["done"].(float64) != 2 || out["failed"].(float64) != 1 {
		t.Fatalf("delete: %d %v", code, out)
	}
	if _, err := db.GetUser(a.ID); err == nil {
		t.Error("пользователь a не удалён")
	}
	if _, err := db.GetUser(c.ID); err != nil {
		t.Error("пользователь c удалён по ошибке")
	}
	if applies != 3 {
		t.Errorf("после удаления ядра пересобраны %d раз, ожидалось 3", applies)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }
