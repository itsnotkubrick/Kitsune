package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
)

func marzbanFile(t *testing.T) []byte {
	p := filepath.Join(t.TempDir(), "m.db")
	d, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, status TEXT, used_traffic INT, data_limit INT, expire INT, note TEXT, on_hold_expire_duration INT)`,
		`INSERT INTO users VALUES (1, 'ivan', 'active', 5, 100, 1800000000, 'n', NULL)`,
	} {
		if _, err := d.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	d.Close()
	b, _ := os.ReadFile(p)
	return b
}

func importRequest(t *testing.T, path string, file []byte, fields map[string]string) *httptest.ResponseRecorder {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	if file != nil {
		fw, _ := w.CreateFormFile("file", "db.sqlite3")
		fw.Write(file)
	}
	w.Close()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/preview", handleImportSources(false, true))
	r.POST("/run", handleImportSources(true, true))
	req := httptest.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestImportAPI(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("TMPDIR", t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	file := marzbanFile(t)

	rec := importRequest(t, "/preview", file, map[string]string{"source": "marzban"})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"create":1`) {
		t.Fatalf("preview: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"warnings":["Импортированные пользователи получат доступ ко всем подключениям Kitsune`) {
		t.Errorf("нет предупреждения о доступе: %s", rec.Body.String())
	}
	var n int
	_ = db.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	if n != 0 {
		t.Fatal("предпросмотр записал в базу")
	}
	if rec := importRequest(t, "/run", file, map[string]string{"source": "marzban"}); rec.Code != 400 {
		t.Errorf("запуск без подтверждения: %d", rec.Code)
	}
	if rec := importRequest(t, "/preview", []byte("не база"), map[string]string{"source": "marzban"}); rec.Code != 400 {
		t.Errorf("битый файл: %d", rec.Code)
	}
	if rec := importRequest(t, "/preview", file, map[string]string{"source": "3xui"}); rec.Code != 400 {
		t.Errorf("чужая схема: %d", rec.Code)
	}
	if rec := importRequest(t, "/preview", nil, map[string]string{"source": "marzban"}); rec.Code != 400 {
		t.Errorf("без файла: %d", rec.Code)
	}
	rec = importRequest(t, "/run", file, map[string]string{"source": "marzban", "confirm": "yes"})
	if rec.Code != 200 {
		t.Fatalf("run: %d %s", rec.Code, rec.Body.String())
	}
	var out struct{ Backup string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if _, err := os.Stat(filepath.Join("backups", out.Backup)); err != nil {
		t.Errorf("копии базы нет: %v", err)
	}
	_ = db.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	if n != 1 {
		t.Errorf("пользователей %d", n)
	}
	// Временные файлы загрузки удалены.
	left, _ := filepath.Glob(filepath.Join("import-tmp", "kitsune-*"))
	if len(left) != 0 {
		t.Errorf("остались временные файлы: %v", left)
	}
}
