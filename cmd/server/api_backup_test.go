package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestBackupExportRejectsInvalidPasswordField(t *testing.T) {
	r := gin.New()
	r.POST("/backup", handleExportBackup)
	for _, body := range []string{"", "{}", `{"password":null}`, `{"password":""}invalid`, `{"password":123}`} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/backup", strings.NewReader(body)))
		if w.Code != http.StatusBadRequest || w.Header().Get("Content-Disposition") != "" {
			t.Fatalf("body %q: status %d, Content-Disposition %q", body, w.Code, w.Header().Get("Content-Disposition"))
		}
	}
}
