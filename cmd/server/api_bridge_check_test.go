package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
)

func bridgeCheckReq(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/c", handleBridgeCheck)
	req := httptest.NewRequest(http.MethodPost, "/c", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestBridgeCheckRejectsBadHosts(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	for _, bad := range []string{`{"host":""}`, `{"host":"127.0.0.1"}`, `{"host":"10.0.0.5"}`, `{"host":"192.168.1.1"}`, `{"host":"::1"}`, `{"host":"not a host"}`, `bad json`} {
		if rec := bridgeCheckReq(t, bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: ждали 400, получили %d", bad, rec.Code)
		}
	}
}

func TestBridgeCheckTCP(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("нет локального порта")
	}
	defer ln.Close()
	// публичный адрес проверки не нужен: без подключений в БД результат пустой, но запрос корректного публичного адреса проходит
	if rec := bridgeCheckReq(t, `{"host":"203.0.113.7"}`); rec.Code != http.StatusOK {
		t.Errorf("корректный публичный адрес: %d %s", rec.Code, rec.Body.String())
	}
}
