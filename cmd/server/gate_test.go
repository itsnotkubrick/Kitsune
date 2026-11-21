package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
)

func gateRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gateMiddleware())
	ok := func(c *gin.Context) { c.String(200, "ok") }
	r.GET("/", ok)
	r.GET("/api/health", ok)
	r.GET("/api/v1/inbounds", ok)
	r.GET("/sub/:id", ok)
	return r
}

func hit(r http.Handler, path, remote, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	req.RemoteAddr = remote
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: gateCookie, Value: cookie})
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestSecretPathGate(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	r := gateRouter()

	// без секретного пути всё работает как раньше
	_ = db.SetSetting("panel_path", "")
	if w := hit(r, "/", "203.0.113.9:5000", ""); w.Code != 200 {
		t.Fatalf("без пути панель должна открываться: %d", w.Code)
	}

	_ = db.SetSetting("panel_path", "abcde12345")
	for _, p := range []string{"/", "/api/v1/inbounds", "/static/js/core.js", "/abcde1234", "/wrong/"} {
		if w := hit(r, p, "203.0.113.9:5000", ""); w.Code != 404 {
			t.Errorf("%s без пропуска должен давать 404, получено %d", p, w.Code)
		}
	}
	if w := hit(r, "/sub/xyz", "203.0.113.9:5000", ""); w.Code != 200 {
		t.Errorf("подписка должна открываться без пути: %d", w.Code)
	}
	if w := hit(r, "/api/health", "203.0.113.9:5000", ""); w.Code != 404 {
		t.Errorf("health снаружи должен быть скрыт: %d", w.Code)
	}
	if w := hit(r, "/api/health", "127.0.0.1:5000", ""); w.Code != 200 {
		t.Errorf("health с самого сервера должен работать: %d", w.Code)
	}
	// вход по секретному пути выдаёт пропуск
	w := hit(r, "/abcde12345/", "203.0.113.9:5000", "")
	if w.Code != 200 {
		t.Fatalf("секретный путь должен открывать панель: %d", w.Code)
	}
	var gate string
	for _, c := range w.Result().Cookies() {
		if c.Name == gateCookie {
			gate = c.Value
		}
	}
	if gate == "" {
		t.Fatal("секретный путь не выдал пропуск")
	}
	if w := hit(r, "/api/v1/inbounds", "203.0.113.9:5000", gate); w.Code != 200 {
		t.Errorf("с пропуском API должен быть доступен: %d", w.Code)
	}
	if w := hit(r, "/api/v1/inbounds", "203.0.113.9:5000", "подделка"); w.Code != 404 {
		t.Errorf("чужой пропуск не должен работать: %d", w.Code)
	}
}

func TestSubOnlyHidesEverythingElse(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	h := subOnly(ok)
	for p, want := range map[string]int{"/sub/abc": 200, "/": 404, "/api/v1/login": 404, "/static/js/core.js": 404} {
		req := httptest.NewRequest("GET", p, nil)
		req.RemoteAddr = "203.0.113.9:1"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != want {
			t.Errorf("%s: ожидалось %d, получено %d", p, want, w.Code)
		}
	}
}
