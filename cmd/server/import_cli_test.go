package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kitsune/internal/db"
)

func TestResolveImportPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KIT_CWD", "")
	if p, err := resolveImportPath("~/x-ui.db"); err != nil || p != filepath.Join(home, "x-ui.db") {
		t.Errorf("тильда: %q %v", p, err)
	}
	if p, err := resolveImportPath("/a/../b/x.db"); err != nil || p != "/b/x.db" {
		t.Errorf("абсолютный: %q %v", p, err)
	}
	// старая обёртка (без KIT_CWD): относительный путь, которого нет, – понятная подсказка
	if _, err := resolveImportPath("нет-такого.db"); err == nil || !strings.Contains(err.Error(), "полный путь") {
		t.Errorf("относительный без KIT_CWD: %v", err)
	}
	// новая обёртка: путь считается от каталога, откуда вызвали kit
	cwd := t.TempDir()
	t.Setenv("KIT_CWD", cwd)
	if p, err := resolveImportPath("sub/x-ui.db"); err != nil || p != filepath.Join(cwd, "sub", "x-ui.db") {
		t.Errorf("KIT_CWD: %q %v", p, err)
	}
}

// Ошибка в меню не закрывает его: без прямого вызова cmdImport возвращает ошибку, а не завершает процесс.
func TestCmdImportErrorReturns(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KIT_CWD", "")
	directCall = false
	err := cmdImport([]string{"xray", filepath.Join(t.TempDir(), "missing.json")})
	if err == nil || !strings.Contains(err.Error(), "не найден") {
		t.Errorf("ждали ошибку, получили %v", err)
	}
	if db.DB != nil {
		_ = db.DB.Close()
	}
}

// Консольный запуск пишет и синхронизирует членство, но ядра не применяет (applyCores в процессе консоли не вызывается).
func TestRunImportConsoleSyncsOnly(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("TMPDIR", t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	f := filepath.Join(t.TempDir(), "x-ui.db")
	if err := os.WriteFile(f, importTestXUI(t), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, _, warn, err := runImport(importReq{source: "3xui", path: f, apply: true})
	if err != nil || warn != "" {
		t.Fatalf("%v %q", err, warn)
	}
	var n int
	_ = db.DB.QueryRow("SELECT COUNT(*) FROM clients").Scan(&n)
	if rep.UserSum.Create != 1 || rep.InSum.Create != 1 || n != 1 {
		t.Errorf("итог %+v %+v, clients=%d", rep.UserSum, rep.InSum, n)
	}
}
