package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"kitsune/internal/db"
)

func TestImportBusyReturns409(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	importMu.Lock()
	rec := importRequest(t, "/preview", marzbanFile(t), map[string]string{"source": "marzban"})
	importMu.Unlock()
	if rec.Code != 409 {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	if left, _ := filepath.Glob(filepath.Join("import-tmp", "kitsune-*")); len(left) != 0 {
		t.Errorf("файл записан на диск до проверки занятости: %v", left)
	}
}

func TestImportBackupNamesAndRotation(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	if err := os.MkdirAll("backups", 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join("backups", "before-restore-1.db"), []byte("x"), 0o600)
	file := marzbanFile(t)
	seen := map[string]bool{}
	for i := 0; i < 7; i++ {
		rec := importRequest(t, "/run", file, map[string]string{"source": "marzban", "confirm": "yes", "mode": "update"})
		if rec.Code != 200 {
			t.Fatalf("run %d: %d %s", i, rec.Code, rec.Body.String())
		}
		var out struct{ Backup string }
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if seen[out.Backup] {
			t.Fatalf("имя копии повторилось: %s", out.Backup)
		}
		seen[out.Backup] = true
	}
	m, _ := filepath.Glob(filepath.Join("backups", "before-import-*.db"))
	if len(m) != importBackupsKeep {
		t.Errorf("копий %d, ожидалось %d", len(m), importBackupsKeep)
	}
	if _, err := os.Stat(filepath.Join("backups", "before-restore-1.db")); err != nil {
		t.Errorf("чужая копия удалена: %v", err)
	}
	if st, _ := os.Stat("backups"); st.Mode().Perm() != 0o700 {
		t.Errorf("права backups: %v", st.Mode().Perm())
	}
}
