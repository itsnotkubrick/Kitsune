package main

import (
	"bufio"
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
)

const testXrayConfig = `{"inbounds":[{"tag":"R","port":443,"protocol":"vless","settings":{"clients":[]},
 "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverNames":["www.example.com"],"dest":"www.example.com:443"}}}]}`

func configRequest(t *testing.T, path string, file []byte, cfg string, fields map[string]string) *httptest.ResponseRecorder {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	fw, _ := w.CreateFormFile("file", "db.sqlite3")
	fw.Write(file)
	if cfg != "" {
		cw, _ := w.CreateFormFile("config", "xray_config.json")
		cw.Write([]byte(cfg))
	}
	w.Close()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/preview", handleImportSources(false, true))
	req := httptest.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestImportMarzbanWithConfigUpload(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	rec := configRequest(t, "/preview", marzbanFile(t), testXrayConfig, map[string]string{"source": "marzban"})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"inbound_sum":{"create":1`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	// Без файла настроек подключений нет.
	rec = configRequest(t, "/preview", marzbanFile(t), "", map[string]string{"source": "marzban"})
	if rec.Code != 200 || strings.Contains(rec.Body.String(), `"inbound_sum":{"create":1`) {
		t.Fatalf("без config: %d %s", rec.Code, rec.Body.String())
	}
	// Битый файл настроек отклоняет весь запуск.
	rec = configRequest(t, "/preview", marzbanFile(t), "{ nope", map[string]string{"source": "marzban"})
	if rec.Code != 400 {
		t.Errorf("битый config: %d", rec.Code)
	}
	// Источник xray: основной файл – config.json.
	rec = configRequest(t, "/preview", []byte(testXrayConfig), "", map[string]string{"source": "xray"})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"inbound_sum":{"create":1`) {
		t.Errorf("xray: %d %s", rec.Code, rec.Body.String())
	}
	if l := leftovers(); len(l) != 0 {
		t.Errorf("остатки: %v", l)
	}
}

func TestImportCLIConfigFlag(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := cmdImport([]string{"3xui", "/x.db", "--config", "/c.json"}); err == nil {
		t.Error("--config только для marzban")
	}
	if err := cmdImport([]string{"marzban", "/x.db", "--config"}); err == nil {
		t.Error("--config без пути")
	}
}

func apiRequest(t *testing.T, fields map[string]string) *httptest.ResponseRecorder {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	w.Close()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/preview", handleImportSources(false, true))
	r.POST("/run", handleImportSources(true, true))
	req := httptest.NewRequest(http.MethodPost, "/run", &body)
	if fields["confirm"] == "" {
		req = httptest.NewRequest(http.MethodPost, "/preview", &body)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestImportMarzbanAPI(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good-token" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/api/users" {
			w.Write([]byte(`{"users":[{"username":"ivan","status":"active","used_traffic":5,"data_limit":100,"expire":1800000000,"proxies":{}}],"total":1}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	rec := apiRequest(t, map[string]string{"source": "marzban-api", "url": srv.URL, "token": "good-token"})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"user_sum":{"create":1`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "good-token") {
		t.Error("токен в ответе")
	}
	rec = apiRequest(t, map[string]string{"source": "marzban-api", "url": srv.URL, "token": "bad-token"})
	if rec.Code != 400 || strings.Contains(rec.Body.String(), "bad-token") {
		t.Errorf("неверный токен: %d %s", rec.Code, rec.Body.String())
	}
	rec = apiRequest(t, map[string]string{"source": "marzban-api", "url": "http://example.com", "token": "t"})
	if rec.Code != 400 {
		t.Errorf("http не к localhost: %d", rec.Code)
	}
	rec = apiRequest(t, map[string]string{"source": "marzban-api", "url": srv.URL})
	if rec.Code != 400 {
		t.Errorf("без доступа: %d", rec.Code)
	}
	// Запись: только с подтверждением, пользователь создаётся.
	rec = apiRequest(t, map[string]string{"source": "marzban-api", "url": srv.URL, "token": "good-token", "confirm": "yes"})
	if rec.Code != 200 {
		t.Fatalf("run: %d %s", rec.Code, rec.Body.String())
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE name = 'ivan'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("пользователь не создан: %d %v", n, err)
	}
	if l := leftovers(); len(l) != 0 {
		t.Errorf("остатки: %v", l)
	}
}

func TestImportCLIMarzbanAPIChecks(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, u := range []string{"http://example.com", "https://u:p@example.com", "ftp://x"} {
		if err := cmdImport([]string{"marzban-api", u}); err == nil {
			t.Errorf("%q: ждали отказ", u)
		}
	}
	// Переменные окружения читаются один раз и сразу убираются.
	t.Setenv("KIT_MARZBAN_TOKEN", " env-token ")
	a := askAPIAuth(bufio.NewReader(strings.NewReader("")), false)
	if a.Token != "env-token" || os.Getenv("KIT_MARZBAN_TOKEN") != "" {
		t.Errorf("env: %+v %q", a, os.Getenv("KIT_MARZBAN_TOKEN"))
	}
	a = askAPIAuth(bufio.NewReader(strings.NewReader("\nroot\nsecret\n")), false)
	if a.Username != "root" || a.Password != "secret" || a.Token != "" {
		t.Errorf("ввод: %+v", a)
	}
	a.Clear()
	if !a.Empty() {
		t.Error("Clear не стёр значения")
	}
}

// Меню не берёт доступ из окружения без согласия: по умолчанию спрашивает как обычно.
func TestImportMenuEnvAccessNeedsConsent(t *testing.T) {
	t.Setenv("KIT_MARZBAN_TOKEN", "env-token")
	a := askAPIAuth(bufio.NewReader(strings.NewReader("\ntyped-token\n")), true)
	if a.Token != "typed-token" {
		t.Errorf("без согласия взято не введённое значение: %+v", a)
	}
	t.Setenv("KIT_MARZBAN_TOKEN", "env-token")
	a = askAPIAuth(bufio.NewReader(strings.NewReader("y\n")), true)
	if a.Token != "env-token" || os.Getenv("KIT_MARZBAN_TOKEN") != "" {
		t.Errorf("с согласием: %+v", a)
	}
}

func TestReleaseImportRejectsMigrationSources(t *testing.T) {
	t.Chdir(t.TempDir())
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/preview", handleImport(false))
	router.POST("/run", handleImport(true))
	for _, path := range []string{"/preview", "/run"} {
		for _, source := range []string{"3xui", "marzban", "marzban-api"} {
			var body bytes.Buffer
			w := multipart.NewWriter(&body)
			_ = w.WriteField("source", source)
			_ = w.WriteField("confirm", "yes")
			file, err := w.CreateFormFile("file", "input.db")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = file.Write([]byte("fixture"))
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, path, &body)
			req.Header.Set("Content-Type", w.FormDataContentType())
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Поддерживается только config.json Xray") {
				t.Fatalf("%s %s: %d %s", path, source, rec.Code, rec.Body.String())
			}
		}
	}
}
