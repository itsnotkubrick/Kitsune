package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func csrfRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(csrfGuard())
	r.POST("/x", func(c *gin.Context) { c.String(200, "ok") })
	r.GET("/x", func(c *gin.Context) { c.String(200, "ok") })
	return r
}

func TestCSRFGuard(t *testing.T) {
	r := csrfRouter()
	cases := []struct {
		name    string
		method  string
		headers map[string]string
		body    string
		want    int
	}{
		{"GET без проверок", "GET", map[string]string{"Origin": "https://evil.example"}, "", 200},
		{"тот же Origin", "POST", map[string]string{"Origin": "http://panel.test", "Content-Type": "application/json"}, "{}", 200},
		{"чужой Origin", "POST", map[string]string{"Origin": "https://evil.example", "Content-Type": "application/json"}, "{}", 403},
		{"Origin null", "POST", map[string]string{"Origin": "null", "Content-Type": "application/json"}, "{}", 403},
		{"чужой Referer", "POST", map[string]string{"Referer": "https://evil.example/a", "Content-Type": "application/json"}, "{}", 403},
		{"Sec-Fetch-Site cross-site", "POST", map[string]string{"Sec-Fetch-Site": "cross-site"}, "", 403},
		{"без заголовков (curl)", "POST", map[string]string{"Content-Type": "application/json"}, "{}", 200},
		{"text/plain с телом", "POST", map[string]string{"Origin": "http://panel.test", "Content-Type": "text/plain"}, "{}", 415},
		{"форма", "POST", map[string]string{"Origin": "http://panel.test", "Content-Type": "application/x-www-form-urlencoded"}, "a=1", 415},
		{"пустое тело без типа", "POST", map[string]string{"Origin": "http://panel.test"}, "", 200},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, "http://panel.test/x", strings.NewReader(tc.body))
		for k, v := range tc.headers {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Errorf("%s: код %d, ждали %d", tc.name, w.Code, tc.want)
		}
	}
}

func TestIsSecureRequestIgnoresForgedHeader(t *testing.T) {
	t.Setenv("KITSUNE_TRUSTED_PROXIES", "")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "http://panel.test/", nil)
	c.Request.Header.Set("X-Forwarded-Proto", "https")
	if isSecureRequest(c) {
		t.Fatal("без доверенных прокси заголовку верить нельзя")
	}
	t.Setenv("KITSUNE_TRUSTED_PROXIES", "10.0.0.0/24")
	if isSecureRequest(c) {
		t.Fatal("адрес вне доверенной сети не должен задавать схему")
	}
	c.Request.RemoteAddr = "10.0.0.1:12345"
	if !isSecureRequest(c) {
		t.Fatal("с доверенным прокси заголовок должен приниматься")
	}
}

func TestValidHostName(t *testing.T) {
	for h, want := range map[string]bool{"203.0.113.5": true, "vpn.example.com": true, "2001:db8::1": true,
		"evil.com/x": false, "a b.com": false, "x@y.com": false, "": false} {
		if got := validHostName(h); got != want {
			t.Errorf("%q: %v, ждали %v", h, got, want)
		}
	}
}

func TestValidateCustomCertRejectsSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.pem")
	_ = os.WriteFile(empty, nil, 0o600)
	for _, p := range [][2]string{
		{"", ""}, {"relative.pem", "relative.key"}, {"/dev/zero", "/dev/zero"},
		{"/proc/self/environ", "/proc/self/environ"}, {dir + "/../etc/passwd", empty},
		{empty, empty}, {filepath.Join(dir, "нет.pem"), empty},
	} {
		if err := validateCustomCert(p[0], p[1]); err == nil {
			t.Errorf("%v: ожидали отказ", p)
		}
	}
	// обычный файл, но не сертификат: отказ на разборе
	junk := filepath.Join(dir, "junk.pem")
	_ = os.WriteFile(junk, []byte("не сертификат"), 0o600)
	if err := validateCustomCert(junk, junk); err == nil {
		t.Error("мусор принят за сертификат")
	}
}
