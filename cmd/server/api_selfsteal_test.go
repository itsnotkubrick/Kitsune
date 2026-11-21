package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
)

func selfstealReq(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/s", handleSelfStealSet)
	req := httptest.NewRequest(http.MethodPost, "/s", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestSelfStealValidation(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	for _, bad := range []string{`{"domain":""}`, `{"domain":"https://vpn.example.com"}`, `{"domain":"не домен"}`, `{"domain":"192.0.2.1"}`, `not json`} {
		if rec := selfstealReq(t, bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: ждали 400, получили %d", bad, rec.Code)
		}
	}
	// нет REALITY-подключений: заглушке нечего подменять
	rec := selfstealReq(t, `{"domain":"vpn.example.com"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "нет подключений") && !strings.Contains(rec.Body.String(), "Нет подключений") {
		t.Errorf("без подключений ждали отказ: %d %s", rec.Code, rec.Body.String())
	}
}
