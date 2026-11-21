package main

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
)

func stabilityRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/sub/stability/:token", handleStabilityPage)
	r.GET("/sub/stability/:token/blob", handleStabilityBlob)
	r.POST("/sub/stability/:token/result", handleStabilityResult)
	r.GET("/sub/:subid", func(c *gin.Context) { c.String(200, "sub") })
	r.GET("/sub/:subid/connect", func(c *gin.Context) { c.String(200, "connect") })
	return r
}

func TestStabilityFlow(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	tok, _ := db.NewStabilityLink()
	r := stabilityRouter()
	do := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}
	if rec := do("GET", "/sub/stability/"+tok, ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Проверка соединения") || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "connect-src 'self'") {
		t.Fatalf("страница: %d", rec.Code)
	}
	rec := do("GET", "/sub/stability/"+tok+"/blob", "")
	if rec.Code != 200 || rec.Body.Len() != stabilitySize || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("файл: код %d, размер %d", rec.Code, rec.Body.Len())
	}
	if bytes.Equal(rec.Body.Bytes()[:64], make([]byte, 64)) {
		t.Error("файл должен быть случайным, а не нулями")
	}
	if do("GET", "/sub/stability/нет-такой", "").Code != 404 || do("GET", "/sub/stability/нет-такой/blob", "").Code != 404 {
		t.Error("неизвестная ссылка даёт 404")
	}
	// маршруты подписок не сломались соседством со страницей проверки
	if do("GET", "/sub/abc", "").Body.String() != "sub" || do("GET", "/sub/abc/connect", "").Body.String() != "connect" {
		t.Error("обычные адреса подписки должны работать")
	}
	do("POST", "/sub/stability/"+tok+"/result", `{"kind":"mobile","note":"Оператор","ok":false,"bytes":6000,"ms":5200}`)
	// «скачалось» без полного файла не принимается как успех
	do("POST", "/sub/stability/"+tok+"/result", `{"kind":"home","ok":true,"bytes":1000,"ms":10}`)
	if c := do("POST", "/sub/stability/"+tok+"/result", `{"ok":true,"bytes":999999999}`).Code; c != 400 {
		t.Errorf("лишний размер должен отклоняться, код %d", c)
	}
	res := db.GetStabilityResults(10)
	if len(res) != 2 || res[0].OK || res[1].OK || res[1].Note != "Оператор" {
		t.Fatalf("результаты: %+v", res)
	}
	do("POST", "/sub/stability/"+tok+"/result", `{"kind":"home","ok":true,"bytes":262144,"ms":900}`)
	if total, stalled, _ := db.StabilitySummary(7); total != 3 || stalled != 2 {
		t.Errorf("итог: %d %d", total, stalled)
	}
}
