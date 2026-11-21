package main

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
	"kitsune/internal/importer"
)

func leftovers() []string {
	m1, _ := filepath.Glob(filepath.Join("import-tmp", "kitsune-*"))
	return m1
}

func TestImportParallelUploads(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	file := marzbanFile(t)
	var wg sync.WaitGroup
	codes := make([]int, 12)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := importRequest(t, "/preview", file, map[string]string{"source": "marzban"})
			codes[i] = rec.Code
		}(i)
	}
	wg.Wait()
	ok, busy := 0, 0
	for _, c := range codes {
		switch c {
		case 200:
			ok++
		case 409:
			busy++
		default:
			t.Errorf("неожиданный код %d", c)
		}
	}
	t.Logf("200: %d, 409: %d", ok, busy)
	if ok == 0 {
		t.Error("ни один не прошёл")
	}
	if l := leftovers(); len(l) != 0 {
		t.Errorf("остатки: %v", l)
	}
}

// Медленная загрузка держит замок; обрыв отпускает его.
func TestImportStalledUploadHoldsLock(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/preview", handleImportSources(false, true))
	srv := httptest.NewServer(r)
	defer srv.Close()
	file := marzbanFile(t)

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	_ = w.WriteField("source", "marzban")
	fw, _ := w.CreateFormFile("file", "db.sqlite3")
	fw.Write(file[:len(file)/2])
	// заголовок обещает больше, чем отправим
	hdr := "POST /preview HTTP/1.1\r\nHost: x\r\nContent-Type: " + w.FormDataContentType() + "\r\nContent-Length: 99999999\r\n\r\n"
	conn.Write([]byte(hdr))
	conn.Write(body.Bytes())
	time.Sleep(400 * time.Millisecond)

	rec := importRequest(t, "/preview", file, map[string]string{"source": "marzban"})
	t.Logf("во время зависшей загрузки: код %d, остатков %d", rec.Code, len(leftovers()))
	if rec.Code != 409 {
		t.Errorf("ждали 409: %d", rec.Code)
	}
	conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	var code int
	for time.Now().Before(deadline) {
		rec = importRequest(t, "/preview", file, map[string]string{"source": "marzban"})
		code = rec.Code
		if code == 200 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code != 200 {
		t.Errorf("после обрыва замок не отпущен: %d", code)
	}
	time.Sleep(200 * time.Millisecond)
	if l := leftovers(); len(l) != 0 {
		t.Errorf("остатки после обрыва: %v", l)
	}
}

func TestImportStartupCleanupAfterKill(t *testing.T) {
	t.Chdir(t.TempDir())
	root, _ := importer.TempRoot()
	os.MkdirAll(filepath.Join(root, "kitsune-upload-123"), 0o700)
	os.WriteFile(filepath.Join(root, "kitsune-upload-123", "src.db"), []byte(strings.Repeat("x", 1<<20)), 0o600)
	os.MkdirAll(filepath.Join(root, "kitsune-import-456"), 0o700)
	importer.CleanTempMinAge = 0
	importer.CleanTemp()
	if l := leftovers(); len(l) != 0 {
		t.Errorf("остатки: %v", l)
	}
	st, _ := os.Stat(root)
	if st.Mode().Perm() != 0o700 {
		t.Errorf("права %v", st.Mode().Perm())
	}
}

func TestImportUploadPermsAndNoLeakOnReject(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	// мусор вместо базы
	rec := importRequest(t, "/preview", []byte("not a database at all"), map[string]string{"source": "3xui"})
	if rec.Code != 400 {
		t.Errorf("мусор: %d", rec.Code)
	}
	// без confirm
	rec = importRequest(t, "/run", marzbanFile(t), map[string]string{"source": "marzban"})
	if rec.Code != 400 {
		t.Errorf("без confirm: %d", rec.Code)
	}
	if l := leftovers(); len(l) != 0 {
		t.Errorf("остатки: %v", l)
	}
	if st, err := os.Stat("import-tmp"); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("import-tmp: %v %v", st, err)
	}
	_ = io.Discard
	_ = http.StatusOK
}

// rotation: чужие файлы с похожими именами; симлинк в backups; параллельный запуск
func TestImportRotationHostile(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	os.MkdirAll("backups", 0o755)
	os.WriteFile(filepath.Join("backups", "before-import.db"), []byte("x"), 0o600)       // без дефиса
	os.WriteFile(filepath.Join("backups", "before-import-keep.txt"), []byte("x"), 0o600) // другое расширение
	os.WriteFile(filepath.Join("backups", "Before-import-1.db"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join("backups", "kitsune-2026.db"), []byte("x"), 0o600)
	outside := filepath.Join(t.TempDir(), "outside.db")
	os.WriteFile(outside, []byte("precious"), 0o600)
	os.Symlink(outside, filepath.Join("backups", "before-import-0000-link.db"))
	os.MkdirAll(filepath.Join("backups", "before-import-dir.db"), 0o700)
	// старые "свои"
	for i := 0; i < 8; i++ {
		p := filepath.Join("backups", "before-import-2020010"+string(rune('1'+i))+".db")
		os.WriteFile(p, []byte("old"), 0o600)
		old := time.Now().Add(-time.Duration(100-i) * time.Hour)
		os.Chtimes(p, old, old)
	}
	file := marzbanFile(t)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			importRequest(t, "/run", file, map[string]string{"source": "marzban", "confirm": "yes", "mode": "update"})
		}()
	}
	wg.Wait()
	rec := importRequest(t, "/run", file, map[string]string{"source": "marzban", "confirm": "yes", "mode": "update"})
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	for _, n := range []string{"before-import.db", "before-import-keep.txt", "Before-import-1.db", "kitsune-2026.db", "before-import-dir.db"} {
		if _, err := os.Lstat(filepath.Join("backups", n)); err != nil {
			t.Errorf("пропал %s", n)
		}
	}
	if b, _ := os.ReadFile(outside); string(b) != "precious" {
		t.Error("файл по симлинку изменён")
	}
	m, _ := filepath.Glob(filepath.Join("backups", "before-import-*.db"))
	for _, p := range m {
		st, _ := os.Lstat(p)
		t.Logf("%s %v %v", filepath.Base(p), st.Mode(), st.ModTime().Format("2006-01-02"))
	}
}

func TestImportAPIWarningsJSON(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	rec := importRequest(t, "/preview", marzbanFile(t), map[string]string{"source": "marzban"})
	if !strings.Contains(rec.Body.String(), `"warnings":["Импортированные пользователи получат доступ`) {
		t.Errorf("в JSON нет warnings: %.300s", rec.Body.String())
	}
	rec = importRequest(t, "/run", marzbanFile(t), map[string]string{"source": "marzban", "confirm": "yes"})
	if !strings.Contains(rec.Body.String(), `"warnings"`) {
		t.Errorf("run: нет warnings")
	}
	rec = importRequest(t, "/preview", marzbanFile(t), map[string]string{"source": "marzban"})
	if strings.Contains(rec.Body.String(), `"warnings"`) {
		t.Errorf("повтор без новых пользователей: предупреждение есть")
	}
}

// Часы ушли назад (или у старых копий время в будущем): свежая копия не должна удаляться сразу после импорта.
func TestImportRotationClockSkew(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	os.MkdirAll("backups", 0o700)
	for i := 0; i < 5; i++ {
		p := filepath.Join("backups", "before-import-2099010"+string(rune('1'+i))+".db")
		os.WriteFile(p, []byte("old"), 0o600)
		fut := time.Now().Add(365 * 24 * time.Hour)
		os.Chtimes(p, fut, fut)
	}
	rec := importRequest(t, "/run", marzbanFile(t), map[string]string{"source": "marzban", "confirm": "yes"})
	var out struct{ Backup string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if _, err := os.Stat(filepath.Join("backups", out.Backup)); err != nil {
		t.Errorf("копия %s, о которой сообщили пользователю, удалена ротацией: %v", out.Backup, err)
	}
}
