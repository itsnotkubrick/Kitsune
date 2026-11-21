package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
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

const importTestUUID = "11111111-2222-4333-8444-555555555555"

func importTestXUI(t *testing.T) []byte {
	p := filepath.Join(t.TempDir(), "x.db")
	d, _ := sql.Open("sqlite", "file:"+p)
	defer d.Close()
	for _, q := range []string{
		`CREATE TABLE inbounds (id integer PRIMARY KEY, remark text, enable numeric, port integer, protocol text, settings text, stream_settings text, tag text)`,
		`CREATE TABLE client_traffics (id integer PRIMARY KEY, email text, up integer, down integer)`,
		`INSERT INTO inbounds VALUES (1,'T',1,2083,'trojan','{"clients":[{"password":"SECRETTROJANPASS","email":"bob","subId":"SECRETSUBID123","id":"` + importTestUUID + `","enable":true}]}','{"network":"grpc","security":"tls","grpcSettings":{"serviceName":"s"}}','t')`,
		`INSERT INTO client_traffics VALUES (1,'bob',100,200)`,
	} {
		if _, err := d.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(p)
	return b
}

func importTestReq(t *testing.T, path string, file []byte, fields map[string]string) *httptest.ResponseRecorder {
	return importRequest(t, path, file, fields)
}

func TestImportAPIAPI(t *testing.T) {
	t.Chdir(t.TempDir())
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	db.InitDB()
	defer db.DB.Close()
	f := importTestXUI(t)

	rec := importTestReq(t, "/preview", f, map[string]string{"source": "3xui"})
	if rec.Code != 200 {
		t.Fatalf("preview %d %s", rec.Code, rec.Body.String())
	}
	for _, secret := range []string{"SECRETTROJANPASS", "SECRETSUBID123", importTestUUID, "privateKey"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("в отчёте секрет %q", secret)
		}
	}
	// без confirm / confirm=no / confirm=YES / mode мусор
	for _, c := range []string{"", "no", "YES", "true", "1"} {
		if r := importTestReq(t, "/run", f, map[string]string{"source": "3xui", "confirm": c}); r.Code != 400 {
			t.Errorf("confirm=%q: %d", c, r.Code)
		}
	}
	for _, s := range []string{"", "x", "3XUI", "Marzban", "marzban "} {
		if r := importTestReq(t, "/preview", f, map[string]string{"source": s}); r.Code != 400 {
			t.Errorf("source=%q: %d", s, r.Code)
		}
	}
	if ents, _ := os.ReadDir("backups"); len(ents) != 0 {
		t.Errorf("копии базы созданы без запуска: %v", ents)
	}
	// run дважды подряд в одну секунду: вторая копия не должна затирать первую
	r1 := importTestReq(t, "/run", f, map[string]string{"source": "3xui", "confirm": "yes"})
	var o1, o2 struct{ Backup string }
	_ = json.Unmarshal(r1.Body.Bytes(), &o1)
	st1, _ := os.Stat(filepath.Join("backups", o1.Backup))
	size1 := st1.Size()
	r2 := importTestReq(t, "/run", f, map[string]string{"source": "3xui", "confirm": "yes"})
	_ = json.Unmarshal(r2.Body.Bytes(), &o2)
	st2, _ := os.Stat(filepath.Join("backups", o2.Backup))
	t.Logf("копии: %s (%d Б) и %s (%d Б); права %v", o1.Backup, size1, o2.Backup, st2.Size(), st2.Mode())
	if o1.Backup == o2.Backup {
		t.Errorf("одно имя копии у двух запусков: вторая затёрла первую (до импорта) – откат на состояние до первого импорта невозможен")
	}
	if st2.Mode().Perm() != 0o600 {
		t.Errorf("права копии %v", st2.Mode())
	}
	if d, _ := os.Stat("backups"); d.Mode().Perm() != 0o700 {
		t.Errorf("права папки backups %v", d.Mode())
	}
	left, _ := os.ReadDir(tmp)
	for _, e := range left {
		t.Errorf("остался временный файл %s", e.Name())
	}
}

func TestImportAPIOversize(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	t.Chdir(t.TempDir())
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	db.InitDB()
	defer db.DB.Close()
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		_ = mw.WriteField("source", "3xui")
		fw, _ := mw.CreateFormFile("file", "big.db")
		fw.Write([]byte("SQLite format 3\x00"))
		chunk := make([]byte, 1<<20)
		for i := 0; i < 270; i++ {
			if _, err := fw.Write(chunk); err != nil {
				break
			}
		}
		mw.Close()
		pw.Close()
	}()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/preview", handleImportSources(false, true))
	req := httptest.NewRequest(http.MethodPost, "/preview", pr)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	t.Logf("код %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	if rec.Code != 400 && rec.Code != 413 {
		t.Errorf("код %d", rec.Code)
	}
	left, _ := os.ReadDir(tmp)
	for _, e := range left {
		t.Errorf("остался временный файл %s", e.Name())
	}
}

func TestImportAPIEmptyAndGarbage(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("TMPDIR", t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	for name, b := range map[string][]byte{"пустой": {}, "16 байт": []byte("SQLite format 3\x00"), "мусор": bytes.Repeat([]byte{0xff}, 5000), "заголовок+мусор": append([]byte("SQLite format 3\x00"), bytes.Repeat([]byte{0xff}, 5000)...)} {
		for _, p := range []string{"/preview", "/run"} {
			rec := importTestReq(t, p, b, map[string]string{"source": "marzban", "confirm": "yes"})
			t.Logf("%s %s -> %d %s", name, p, rec.Code, strings.TrimSpace(rec.Body.String()))
			if rec.Code != 400 && !(name == "пустой" && rec.Code == 400) {
				t.Errorf("%s %s: %d", name, p, rec.Code)
			}
		}
	}
	if ents, _ := os.ReadDir("backups"); len(ents) != 0 {
		t.Errorf("копия базы создана при ошибке чтения файла: %v", ents)
	}
}
