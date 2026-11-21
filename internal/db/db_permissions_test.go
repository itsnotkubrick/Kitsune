package db

import (
	"os"
	"runtime"
	"testing"
)

func TestInitDBRestrictsSQLiteFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions")
	}
	t.Chdir(t.TempDir())
	previous := DB
	t.Cleanup(func() {
		_ = DB.Close()
		DB = previous
	})

	// Simulate an existing database with permissive access before SQLite opens it.
	if err := os.WriteFile("kitsune.db", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod("kitsune.db", 0o644); err != nil {
		t.Fatal(err)
	}
	InitDB()
	for _, name := range []string{"kitsune.db", "kitsune.db-wal", "kitsune.db-shm"} {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s: mode %04o, want 0600", name, mode)
		}
	}
}
