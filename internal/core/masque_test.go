package core

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kitsune/internal/db"
	"kitsune/internal/proto"
)

func TestVersionCmpPrereleases(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.15.0-alpha.13", "1.15.0-alpha.9", 1}, // alpha.13 новее alpha.9: числа, а не строки
		{"1.15.0-alpha.9", "1.15.0-alpha.13", -1},
		{"1.15.0", "1.15.0-rc.1", 1},
		{"1.15.0-rc.1", "1.15.0-alpha.13", 1},
		{"1.15.0-alpha.13", "1.14.4", 1},
		{"1.14.4", "1.15.0-alpha.1", -1},
		{"v1.15.0-alpha.13", "1.15.0-alpha.13", 0},
		{"1.15.1-alpha.1", "1.15.0", 1},
		{"1.15.0-alpha", "1.15.0-alpha.1", -1},
	} {
		if got := versionCmp(c.a, c.b); got != c.want {
			t.Errorf("versionCmp(%q,%q)=%d, ждали %d", c.a, c.b, got, c.want)
		}
	}
	// у MASQUE предрелиз сравнивается по semver, у остальных ядер версия с хвостом по-прежнему не считается новее
	if !newerFor("masque", "1.15.0-alpha.14", "1.15.0-alpha.13") || newerFor("masque", "1.15.0-alpha.13", "1.15.0-alpha.13") {
		t.Error("masque: alpha.14 должна быть новее alpha.13 и только")
	}
	if newerFor("singbox", "1.15.0-alpha.14", "1.14.3") {
		t.Error("у обычного sing-box предрелиз не должен считаться новее")
	}
}

const masqueReleases = `[
 {"tag_name":"v1.14.4","published_at":"2026-10-24T00:00:00Z","draft":false,"prerelease":false,"assets":[]},
 {"tag_name":"v1.15.0-alpha.13","published_at":"2026-10-24T00:00:00Z","draft":false,"prerelease":true,"assets":[]},
 {"tag_name":"v1.15.0-alpha.14","published_at":"2026-11-01T00:00:00Z","draft":false,"prerelease":true,"assets":[
   {"name":"sing-box-1.15.0-alpha.14-linux-amd64.tar.gz","created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-01T00:00:00Z","digest":"sha256:%s"}]},
 {"tag_name":"v1.99.0","published_at":"2026-11-02T00:00:00Z","draft":true,"prerelease":false,"assets":[]},
 {"tag_name":"v1.15.0-alpha.9","published_at":"2026-09-26T00:00:00Z","draft":false,"prerelease":true,"assets":[]}
]`

func TestMasqueTakesNewestIncludingPrerelease(t *testing.T) {
	sum := strings.Repeat("ef", 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/releases") || strings.HasSuffix(r.URL.Path, "/latest") {
			http.Error(w, "для MASQUE /releases/latest не годится: он пропускает предрелизы", 404)
			return
		}
		w.Write([]byte(strings.Replace(masqueReleases, "%s", sum, 1)))
	}))
	defer srv.Close()
	oldAPI := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = oldAPI }()

	r, err := fetchReleaseFor(context.Background(), "masque", "SagerNet/sing-box")
	if err != nil || r.Tag != "1.15.0-alpha.14" {
		t.Fatalf("ждали alpha.14 (черновик 1.99.0 пропускается, 1.14.4 ниже): %+v %v", r, err)
	}
	a, v, err := latestAsset("masque", masqueAssets["linux-amd64"], true)
	if err != nil || v != "1.15.0-alpha.14" || a.SHA256 != sum ||
		a.URL != "https://github.com/SagerNet/sing-box/releases/download/v1.15.0-alpha.14/sing-box-1.15.0-alpha.14-linux-amd64.tar.gz" {
		t.Fatalf("%+v %q %v", a, v, err)
	}
	// «вышла новая версия»: у установленной alpha.13 появилась alpha.14
	oldBin := versionDir
	versionDir = t.TempDir()
	latestCache.data = map[string]latestEntry{}
	defer func() { versionDir = oldBin; latestCache.data = map[string]latestEntry{} }()
	setInstalledVersion("masque", "1.15.0-alpha.13")
	var got *Latest
	for _, l := range LatestVersions(context.Background()) {
		if l.ID == "masque" {
			l := l
			got = &l
		}
	}
	if got == nil || !got.Newer || got.Latest != "1.15.0-alpha.14" || !strings.Contains(got.Warning, "alpha.14") {
		t.Fatalf("уведомление о новой версии: %+v", got)
	}
	setInstalledVersion("masque", "1.15.0-alpha.14")
	latestCache.data = map[string]latestEntry{}
	for _, l := range LatestVersions(context.Background()) {
		if l.ID == "masque" && l.Newer {
			t.Errorf("при установленной последней версии уведомления быть не должно: %+v", l)
		}
	}
}

func TestMasqueServerAddr(t *testing.T) {
	for in, want := range map[string]string{"10.77.0.0/24": "10.77.0.1/24", "10.8.4.0/28": "10.8.4.1/28", "172.20.0.0/16": "172.20.0.1/16"} {
		if got, err := masqueServerAddr(in); err != nil || got != want {
			t.Errorf("%s -> %q %v, ждали %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "10.77.0.1", "fd00::/64", "10.0.0.0/8", "10.0.0.0/31", "x"} {
		if _, err := masqueServerAddr(bad); err == nil {
			t.Errorf("%q принято", bad)
		}
	}
	if _, err := masqueMTU("1200"); err == nil {
		t.Error("MTU меньше 1280 принят")
	}
	if v, err := masqueMTU(""); err != nil || v != 1280 {
		t.Errorf("MTU по умолчанию: %d %v", v, err)
	}
}

func TestBuildMasqueConfig(t *testing.T) {
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	for _, f := range []string{crt, key} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := proto.Settings{CertMode: "custom", CertFile: crt, KeyFile: key, SNI: "vpn.example.org"}
	if err := s.Fill(proto.Masque); err != nil {
		t.Fatal(err)
	}
	ib := db.Inbound{ID: 5, Tag: "MASQUE", Kind: string(proto.Masque), Port: 8448, Enable: true, Settings: s.JSON()}
	other := db.Inbound{ID: 6, Tag: "TUIC", Kind: string(proto.TUIC), Port: 8444, Enable: true}
	off := db.Inbound{ID: 7, Tag: "M2", Kind: string(proto.Masque), Port: 8449, Enable: false, Settings: s.JSON()}
	users := []db.User{
		{ID: 1, Name: "alice", Password: "pw-alice", Enable: true},
		{ID: 2, Name: "off", Password: "pw-off", Enable: false},
	}
	cfg, any, err := buildMasque([]db.Inbound{ib, other, off}, users, map[int]map[int]bool{}, proto.Env{Host: "203.0.113.5"}, true, SingboxSettings{LogLevel: "info"})
	if err != nil || !any {
		t.Fatalf("%v %v", any, err)
	}
	eps := cfg["endpoints"].([]proto.M)
	if len(eps) != 1 {
		t.Fatalf("нужна одна конечная точка (TUIC и выключенное не в счёт): %v", eps)
	}
	e := eps[0]
	if e["type"] != "masque-server" || e["tag"] != "MASQUE" || e["listen_port"] != 8448 || e["mtu"] != 1280 {
		t.Errorf("%v", e)
	}
	if a := e["address"].([]string); len(a) != 1 || a[0] != "10.77.0.1/24" {
		t.Errorf("адрес сервера в туннеле: %v", a)
	}
	if v := e["version"].([]int); len(v) != 3 {
		t.Errorf("версии HTTP: %v", v)
	}
	us := e["users"].([]proto.M)
	if len(us) != 1 || us[0]["username"] != "alice" || us[0]["password"] != "pw-alice" {
		t.Errorf("пользователи (отключённого быть не должно): %v", us)
	}
	tls := e["tls"].(proto.M)
	if tls["certificate_path"] != crt || tls["key_path"] != key || tls["server_name"] != "vpn.example.org" {
		t.Errorf("tls: %v", tls)
	}
	rules := cfg["route"].(proto.M)["rules"].([]proto.M)
	if len(rules) != 1 || rules[0]["ip_is_private"] != true || rules[0]["action"] != "reject" {
		t.Errorf("частные адреса должны блокироваться: %v", rules)
	}
	if _, has := cfg["inbounds"]; has {
		t.Error("у MASQUE-ядра обычных входов быть не должно, только endpoint")
	}
	// без пользователей запускать нечего
	if _, any, err := buildMasque([]db.Inbound{ib}, nil, nil, proto.Env{}, false, SingboxSettings{}); any || err != nil {
		t.Errorf("без пользователей: any=%v err=%v", any, err)
	}
	// без подключений MASQUE тоже
	if _, any, _ := buildMasque([]db.Inbound{other}, users, nil, proto.Env{}, false, SingboxSettings{}); any {
		t.Error("без подключений MASQUE запускать нечего")
	}
}

// Бинарник MASQUE кладётся как sing-box-masque и не трогает основной sing-box, который лежит рядом.
func TestInstallMasqueRenamesBinary(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sing-box"), []byte("основной"), 0o755); err != nil {
		t.Fatal(err)
	}
	arch := filepath.Join(dir, "a.tar.gz")
	writeTarGz(t, arch, map[string]string{"sing-box-1.15.0-alpha.14-linux-amd64/sing-box": "masque-бинарник", "sing-box-1.15.0-alpha.14-linux-amd64/LICENSE": "x"})
	if err := extractTarGzAs(arch, dir, map[string]os.FileMode{"sing-box": 0o755}, map[string]string{"sing-box": "sing-box-masque"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "sing-box-masque"))
	m, _ := os.ReadFile(filepath.Join(dir, "sing-box"))
	if string(b) != "masque-бинарник" || string(m) != "основной" {
		t.Fatalf("masque=%q основной=%q", b, m)
	}
	if st, _ := os.Stat(filepath.Join(dir, "sing-box-masque")); st == nil || st.Mode()&0o111 == 0 {
		t.Error("бинарник должен быть исполняемым")
	}
}

func writeTarGz(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
}
