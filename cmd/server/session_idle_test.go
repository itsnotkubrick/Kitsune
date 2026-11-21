package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

// idleRouter: /login выдаёт сессию (как настоящий вход), /api защищён AuthRequired.
func idleRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(sessions.Sessions(sessionCookie, cookie.NewStore([]byte("0123456789abcdef0123456789abcdef"))))
	r.POST("/login", func(c *gin.Context) { startSession(sessions.Default(c), "admin", false); c.String(200, "ok") })
	r.GET("/legacy", func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("username", "admin")
		_ = s.Save()
		c.String(200, "ok")
	})
	r.GET("/api", AuthRequired(), func(c *gin.Context) { c.String(200, "data") })
	return r
}

type clock struct{ t time.Time }

func (k *clock) at(d time.Duration) { sessionNow = func() time.Time { return k.t.Add(d) } }

func setClock(t *testing.T) *clock {
	k := &clock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	k.at(0)
	t.Cleanup(func() { sessionNow = time.Now })
	return k
}

func do(r http.Handler, method, path string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// merge накладывает Set-Cookie ответа на текущий набор cookie (как браузер).
func merge(jar []*http.Cookie, w *httptest.ResponseRecorder) []*http.Cookie {
	for _, nc := range w.Result().Cookies() {
		replaced := false
		for i, c := range jar {
			if c.Name == nc.Name {
				jar[i], replaced = nc, true
			}
		}
		if !replaced {
			jar = append(jar, nc)
		}
	}
	return jar
}

func login(t *testing.T, r http.Handler) []*http.Cookie {
	w := do(r, "POST", "/login", nil)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	return merge(nil, w)
}

func TestIdleSessionAliveWithinWindow(t *testing.T) {
	k := setClock(t)
	r := idleRouter()
	jar := login(t, r)
	k.at(29 * time.Minute)
	if w := do(r, "GET", "/api", jar); w.Code != 200 {
		t.Fatalf("за 29 минут сессия должна жить: %d", w.Code)
	}
}

func TestIdleSessionExpiresAfter30MinutesAndClearsCookie(t *testing.T) {
	k := setClock(t)
	r := idleRouter()
	jar := login(t, r)
	k.at(31 * time.Minute)
	w := do(r, "GET", "/api", jar)
	if w.Code != 401 || !strings.Contains(w.Body.String(), `"session_expired":true`) {
		t.Fatalf("после 31 минуты нужен 401 с session_expired: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("ответ об истечении не должен кешироваться")
	}
	jar = merge(jar, w)
	// cookie очищена: следующий запрос – обычный «нужна авторизация», а не новая сессия
	w2 := do(r, "GET", "/api", jar)
	if w2.Code != 401 || strings.Contains(w2.Body.String(), "session_expired") {
		t.Fatalf("после очистки ожидается обычный 401: %d %s", w2.Code, w2.Body.String())
	}
}

func TestIdleWindowSlides(t *testing.T) {
	k := setClock(t)
	r := idleRouter()
	jar := login(t, r)
	for i := 1; i <= 6; i++ { // каждые 20 минут: всего 2 часа, но простоя больше 30 минут нет
		k.at(time.Duration(i) * 20 * time.Minute)
		w := do(r, "GET", "/api", jar)
		if w.Code != 200 {
			t.Fatalf("шаг %d: %d", i, w.Code)
		}
		jar = merge(jar, w)
	}
	k.at(6*20*time.Minute + 31*time.Minute)
	if w := do(r, "GET", "/api", jar); w.Code != 401 {
		t.Fatalf("после простоя 31 минута сессия должна истечь: %d", w.Code)
	}
}

func TestIdleTouchIsThrottled(t *testing.T) {
	k := setClock(t)
	r := idleRouter()
	jar := login(t, r)
	k.at(20 * time.Second)
	w := do(r, "GET", "/api", jar)
	if w.Code != 200 || len(w.Result().Cookies()) != 0 {
		t.Fatalf("опрос раз в 10 секунд не должен переписывать cookie каждый раз: %d, %d cookie", w.Code, len(w.Result().Cookies()))
	}
	k.at(2 * time.Minute)
	if w := do(r, "GET", "/api", jar); len(w.Result().Cookies()) == 0 {
		t.Fatal("через минуту метка активности обновляется")
	}
}

func TestAbsoluteLifetime(t *testing.T) {
	k := setClock(t)
	r := idleRouter()
	jar := login(t, r)
	for i := 1; i <= 35; i++ { // каждые 20 минут до 11 ч 40 мин: простоев больше 30 минут нет
		k.at(time.Duration(i) * 20 * time.Minute)
		w := do(r, "GET", "/api", jar)
		if w.Code != 200 {
			t.Fatalf("шаг %d: %d", i, w.Code)
		}
		jar = merge(jar, w)
	}
	k.at(12*time.Hour + 5*time.Minute)
	w := do(r, "GET", "/api", jar)
	if w.Code != 401 {
		t.Fatalf("через 12 часов вход нужен независимо от активности: %d", w.Code)
	}
}

func TestOldSessionWithoutTimestampsIsRejected(t *testing.T) {
	setClock(t)
	r := idleRouter()
	jar := merge(nil, do(r, "GET", "/legacy", nil)) // сессия старого образца: только username
	if w := do(r, "GET", "/api", jar); w.Code != 401 {
		t.Fatalf("сессия без меток времени должна требовать повторного входа: %d", w.Code)
	}
}

func TestSessionFromTheFutureIsRejected(t *testing.T) {
	k := setClock(t)
	r := idleRouter()
	jar := login(t, r)
	k.at(-3 * time.Hour) // часы ушли назад: метки «из будущего» не продлевают сессию бесконечно
	if w := do(r, "GET", "/api", jar); w.Code != 401 {
		t.Fatalf("метка из будущего: %d", w.Code)
	}
}

func TestSessionIdleSetting(t *testing.T) {
	if sessionIdle() != 30*time.Minute {
		t.Fatalf("по умолчанию 30 минут: %v", sessionIdle())
	}
}
