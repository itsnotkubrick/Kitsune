package main

import (
	"kitsune/internal/site"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// 404 панели: страница nginx и ни одного заголовка панели (они были бы приметой).
func TestNotFoundLooksLikeNginx(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(frameHeaders()) // ставит X-Frame-Options, CSP и другие до ответа
	setupNotFound(r)
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodHead} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(m, "/нет-такого", nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s: код %d", m, w.Code)
		}
		h := w.Header()
		if h.Get("Server") != "nginx" || h.Get("Content-Type") != "text/html" || h.Get("Content-Length") != strconv.Itoa(len(site.NotFoundBody)) {
			t.Fatalf("%s: заголовки не как у nginx: %v", m, h)
		}
		for _, k := range []string{"X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy"} {
			if h.Get(k) != "" {
				t.Fatalf("%s: на 404 остался заголовок панели %s", m, k)
			}
		}
		if m != http.MethodHead && w.Body.String() != site.NotFoundBody {
			t.Fatalf("%s: тело %q", m, w.Body.String())
		}
	}
}

func TestCookieNamesAreNeutral(t *testing.T) {
	for _, n := range []string{gateCookie, sessionCookie} {
		if n == "" || strings.Contains(strings.ToLower(n), "kitsune") {
			t.Fatalf("имя cookie %q называет продукт", n)
		}
	}
}

func TestReservedLocalPorts(t *testing.T) {
	for _, p := range []int{10380, 10398, 10399} {
		if !reservedLocalPort(p) {
			t.Errorf("порт %d должен быть служебным", p)
		}
	}
	if reservedLocalPort(10400) || reservedLocalPort(443) {
		t.Error("лишние порты считаются служебными")
	}
}
