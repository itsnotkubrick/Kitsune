package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAccessLogHidesSubscriptionTokens(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	r := gin.New()
	r.Use(accessLogger(&buf))
	r.GET("/sub/:subid", func(c *gin.Context) { c.String(200, "ok") })
	r.GET("/sub/stability/:token", func(c *gin.Context) { c.String(200, "ok") })
	r.GET("/api/health", func(c *gin.Context) { c.String(200, "ok") })

	for _, u := range []string{"/sub/SECRETTOKEN123?x=1", "/sub/stability/ONETIMETOKEN9", "/sub/unknown-token-xyz", "/api/health", "/secret-panel-path/"} {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, u, nil))
	}
	log := buf.String()
	for _, secret := range []string{"SECRETTOKEN123", "ONETIMETOKEN9", "unknown-token-xyz", "x=1", "secret-panel-path"} {
		if strings.Contains(log, secret) {
			t.Errorf("в журнале остался %q:\n%s", secret, log)
		}
	}
	for _, want := range []string{"/sub/:subid", "/sub/stability/:token", "/api/health"} {
		if !strings.Contains(log, want) {
			t.Errorf("в журнале нет %q:\n%s", want, log)
		}
	}
}
