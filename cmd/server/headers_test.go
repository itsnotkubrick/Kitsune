package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestFrameHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(frameHeaders())
	r.GET("/", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.GET("/sub", func(c *gin.Context) { c.Header("X-Frame-Options", "DENY"); c.String(http.StatusOK, "ok") })
	for path, wantXFO := range map[string]string{"/": "SAMEORIGIN", "/sub": "DENY", "/missing": "SAMEORIGIN"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if got := w.Header().Get("X-Frame-Options"); got != wantXFO {
			t.Errorf("%s: X-Frame-Options = %q, ждали %q", path, got, wantXFO)
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: нет nosniff", path)
		}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Header().Get("Content-Security-Policy") != "frame-ancestors 'self'" {
		t.Errorf("CSP: %q", w.Header().Get("Content-Security-Policy"))
	}
}
