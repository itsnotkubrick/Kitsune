package core

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func sumOf(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func TestFetchFromLocalDir(t *testing.T) {
	dir := t.TempDir()
	data := []byte("core-archive")
	os.WriteFile(filepath.Join(dir, "x.tar.gz"), data, 0o644)
	t.Setenv("KITSUNE_CORES_DIR", dir)
	p, err := fetchVerified(Asset{URL: "http://127.0.0.1:1/dl/x.tar.gz", SHA256: sumOf(data)})
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(p)
}

func TestFetchViaMirrorAndHashStillChecked(t *testing.T) {
	data := []byte("from-mirror")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(data) }))
	defer srv.Close()
	t.Setenv("KITSUNE_GH_MIRROR", srv.URL)
	dead := "http://127.0.0.1:1/f.zip"
	if p, err := fetchVerified(Asset{URL: dead, SHA256: sumOf(data)}); err != nil {
		t.Fatal(err)
	} else {
		os.Remove(p)
	}
	if _, err := fetchVerified(Asset{URL: dead, SHA256: sumOf([]byte("other"))}); err == nil {
		t.Fatal("подменённый файл с зеркала принят")
	}
}
