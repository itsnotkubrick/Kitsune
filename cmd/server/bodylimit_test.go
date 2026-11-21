package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// readAll – обработчик: читает всё тело и говорит, сколько прочитал или какая ошибка.
func bodyEngine() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(bodyLimit())
	h := func(c *gin.Context) {
		n, err := io.Copy(io.Discard, c.Request.Body)
		if err != nil {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "прочитано до ошибки"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"n": n})
	}
	r.POST("/api/v1/login", h)
	r.POST("/api/v1/users", h)
	r.POST("/api/v1/backup/restore", h)
	r.POST("/api/v1/import/run", h)
	return r
}

func post(r *gin.Engine, path string, size int) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(make([]byte, size)))
	r.ServeHTTP(w, req)
	return w
}

func TestBodyLimitDefaultRejectsBigBody(t *testing.T) {
	r := bodyEngine()
	if w := post(r, "/api/v1/login", 4<<10); w.Code != http.StatusOK {
		t.Fatalf("обычный JSON отклонён: %d", w.Code)
	}
	if w := post(r, "/api/v1/login", bodyLimitDefault); w.Code != http.StatusOK {
		t.Fatalf("тело ровно в предел отклонено: %d", w.Code)
	}
	for _, p := range []string{"/api/v1/login", "/api/v1/users"} {
		w := post(r, p, bodyLimitDefault+1)
		if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), "слишком большой") {
			t.Fatalf("%s: тело больше предела должно давать 413, получено %d %s", p, w.Code, w.Body.String())
		}
	}
}

// Тело без Content-Length (chunked): предел действует при чтении.
func TestBodyLimitChunkedBodyStopsAtLimit(t *testing.T) {
	r := bodyEngine()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", io.NopCloser(io.LimitReader(zeroReader{}, 3<<20)))
	req.ContentLength = -1
	r.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked-тело в 3 МБ должно прерываться на пределе, получено %d", w.Code)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { return len(p), nil }

func TestBodyLimitUploadRoutesKeepBigBodies(t *testing.T) {
	r := bodyEngine()
	if w := post(r, "/api/v1/backup/restore", 8<<20); w.Code != http.StatusOK {
		t.Fatalf("восстановление копии в 8 МБ отклонено: %d", w.Code)
	}
	if w := post(r, "/api/v1/import/run", 8<<20); w.Code != http.StatusOK {
		t.Fatalf("импорт в 8 МБ отклонён общим лимитом: %d", w.Code)
	}
}

func TestBodyLimitRestoreHasOwnCeiling(t *testing.T) {
	r := bodyEngine()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/backup/restore", strings.NewReader("x"))
	req.ContentLength = bodyLimitUpload + 1 // заявленный размер больше предела: отказ до чтения
	r.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("заявленные 257 МБ+1 должны давать 413, получено %d", w.Code)
	}
}
