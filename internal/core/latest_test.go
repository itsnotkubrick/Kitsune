package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVersionNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"26.7.1", "26.6.27", true}, {"26.6.27", "26.6.27", false}, {"1.14.4", "1.14.3", true},
		{"1.9.0", "1.14.3", false}, {"2.0.0-rc1", "1.9.0", false}, {"3.38.2", "3.38.1", true},
	} {
		if got := versionNewer(c.a, c.b); got != c.want {
			t.Errorf("versionNewer(%q,%q)=%v", c.a, c.b, got)
		}
	}
}

func TestLatestVersions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "Xray-core") {
			w.Write([]byte(`{"tag_name":"v26.7.1","published_at":"2020-01-01T00:00:00Z"}`))
			return
		}
		if strings.Contains(r.URL.Path, "mtg") {
			http.Error(w, "x", 404)
			return
		}
		w.Write([]byte(`{"tag_name":"` + strings.TrimPrefix(SingboxVersion, "v") + `","published_at":"2020-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()
	oldAPI := githubAPI
	githubAPI = srv.URL
	latestCache.data = map[string]latestEntry{}
	oldBin := versionDir
	versionDir = t.TempDir()
	defer func() { githubAPI = oldAPI; latestCache.data = map[string]latestEntry{}; versionDir = oldBin }()

	got := map[string]Latest{}
	for _, l := range LatestVersions(context.Background()) {
		got[l.ID] = l
	}
	if x := got["xray"]; !x.Newer || x.Latest != "26.7.1" || !strings.Contains(x.Warning, "26.7.1") {
		t.Errorf("xray: %+v", x)
	}
	if m := got["mtg"]; m.Latest != "" || m.Newer || m.Warning != "" {
		t.Errorf("mtg недоступен, но: %+v", m)
	}
}

func TestLatestAssetUsesReleaseDigest(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name":"v9.9.9","published_at":"2020-01-01T00:00:00Z","assets":[` +
			`{"name":"sing-box-9.9.9-linux-amd64.tar.gz","created_at":"2020-01-01T00:00:00Z","updated_at":"2020-01-01T00:00:00Z","digest":"sha256:` + sum + `"},` +
			`{"name":"sing-box-9.9.9-linux-arm64.tar.gz"}]}`))
	}))
	defer srv.Close()
	oldAPI := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = oldAPI }()

	a, v, err := latestAsset("singbox", singboxAssets["linux-amd64"], false)
	if err != nil || v != "9.9.9" || a.SHA256 != sum || !strings.Contains(a.URL, "/v9.9.9/sing-box-9.9.9-linux-amd64.tar.gz") {
		t.Fatalf("%+v %q %v", a, v, err)
	}
	if _, _, err := latestAsset("singbox", singboxAssets["linux-arm64"], false); err == nil {
		t.Error("архив без контрольной суммы принят")
	}
	if _, _, err := latestAsset("singbox", singboxAssets["darwin-arm64"], false); err == nil {
		t.Error("нет такого файла в релизе, а ошибки нет")
	}
}

func TestInstalledVersionMarker(t *testing.T) {
	old := versionDir
	versionDir = t.TempDir()
	defer func() { versionDir = old }()
	if InstalledVersion("mtg") != MTGVersion {
		t.Error("без записи должна быть закреплённая версия")
	}
	setInstalledVersion("mtg", "9.9.9")
	if InstalledVersion("mtg") != "9.9.9" {
		t.Error("запись не прочиталась")
	}
}

func TestYoungReleaseQuarantine(t *testing.T) {
	sum := strings.Repeat("cd", 32)
	young := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":"v9.9.9","published_at":%q,"assets":[{"name":"sing-box-9.9.9-linux-amd64.tar.gz","digest":"sha256:%s"}]}`, young, sum)
	}))
	defer srv.Close()
	oldAPI := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = oldAPI }()
	if _, _, err := latestAsset("singbox", singboxAssets["linux-amd64"], false); err == nil || !strings.Contains(err.Error(), "3 суток") {
		t.Fatalf("свежий релиз принят: %v", err)
	}
	if !quarantined("") || !quarantined("мусор") || quarantined("2020-01-01T00:00:00Z") {
		t.Error("карантин по дате работает неверно")
	}
}

func TestNoSilentDowngrade(t *testing.T) {
	old := versionDir
	versionDir = t.TempDir()
	defer func() { versionDir = old }()
	oldAPI := githubAPI
	githubAPI = "http://127.0.0.1:1" // GitHub недоступен
	defer func() { githubAPI = oldAPI }()
	setInstalledVersion("mtg", "99.0.0")
	err := install("mtg", mtgAssets, "mtg", nil)
	if err == nil || !strings.Contains(err.Error(), "99.0.0") {
		t.Fatalf("новая версия должна остаться, а получено: %v", err)
	}
}

func TestReplacedArchiveInOldRelease(t *testing.T) {
	sum := strings.Repeat("ef", 32)
	fresh := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":"v9.9.9","published_at":"2020-01-01T00:00:00Z","assets":[{"name":"sing-box-9.9.9-linux-amd64.tar.gz","created_at":"2020-01-01T00:00:00Z","updated_at":%q,"digest":"sha256:%s"}]}`, fresh, sum)
	}))
	defer srv.Close()
	oldAPI := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = oldAPI }()
	if _, _, err := latestAsset("singbox", singboxAssets["linux-amd64"], false); err == nil {
		t.Fatal("файл, заменённый час назад в старом релизе, принят")
	}
}

func TestFreshReleaseOnlyWhenAllowed(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	young := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":"v9.9.9","published_at":%q,"assets":[{"name":"sing-box-9.9.9-linux-amd64.tar.gz","created_at":%q,"updated_at":%q,"digest":"sha256:%s"}]}`, young, young, young, sum)
	}))
	defer srv.Close()
	oldAPI := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = oldAPI }()
	if _, _, err := latestAsset("singbox", singboxAssets["linux-amd64"], false); err == nil {
		t.Error("свежий выпуск принят без разрешения")
	}
	a, v, err := latestAsset("singbox", singboxAssets["linux-amd64"], true)
	if err != nil || v != "9.9.9" || a.SHA256 != sum {
		t.Errorf("с разрешением: %+v %q %v", a, v, err)
	}
	if freshAllowed("singbox") {
		t.Error("разрешение осталось включённым")
	}
}
