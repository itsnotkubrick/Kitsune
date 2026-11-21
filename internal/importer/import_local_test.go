package importer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kitsune/internal/proto"
)

func TestIsLocalHost(t *testing.T) {
	local := []string{"localhost", "LOCALHOST.", "localhost.localdomain", "host.localdomain", "a.home.arpa", "127.0.0.1", "10.0.0.5",
		"192.168.1.1", "172.16.0.1", "169.254.1.1", "100.64.0.1", "100.127.255.254", "198.18.0.1", "198.19.255.255", "0.0.0.1", "0",
		"224.0.0.1", "239.1.1.1", "255.255.255.255", "::1", "[::1]", "::", "ff02::1", "2130706433", "0x7f.1", "x.internal", "x.local"}
	for _, h := range local {
		if !isLocalHost(h) {
			t.Errorf("%q должен считаться локальным", h)
		}
	}
	for _, h := range []string{"www.example.com", "8.8.8.8", "100.63.255.255", "100.128.0.1", "198.17.0.1", "198.20.0.1", "1.1.1.1", "2606:4700::1111"} {
		if isLocalHost(h) {
			t.Errorf("%q не должен считаться локальным", h)
		}
	}
}

func TestSNILocalNotUsedAsTarget(t *testing.T) {
	priv, _, _ := proto.RealityKeys()
	for _, sni := range []string{"localhost", "127.0.0.1", "10.0.0.5", "*", "*.example.com", "100.64.0.1"} {
		for _, target := range []string{"", "127.0.0.1:2053"} {
			rs := m{"serverNames": []string{sni}, "privateKey": priv, "shortIds": []string{"ab"}, "settings": m{"fingerprint": "chrome"}}
			if target != "" {
				rs["target"] = target
			}
			d, p := realXUI(t)
			addInbound(t, d, "r", 443, "vless", `{"clients":[]}`, jsonOf(t, m{"network": "tcp", "security": "reality", "realitySettings": rs}))
			data, err := Read3XUI(p)
			if err != nil {
				t.Fatal(err)
			}
			in := data.Inbounds[0]
			if in.Kind != "" || in.SkipReason == "" {
				t.Errorf("sni=%q target=%q: подключение не пропущено (kind=%q)", sni, target, in.Kind)
			}
			if strings.Contains(in.Settings.Target, "127.0.0.1") || strings.Contains(in.Settings.Target, "10.0.0.5") {
				t.Errorf("sni=%q: локальный target %q", sni, in.Settings.Target)
			}
		}
	}
}

func TestEmptySNISkipped(t *testing.T) {
	priv, _, _ := proto.RealityKeys()
	for _, sni := range []string{"", "...", "-", "a..b", ".example.com"} {
		for _, target := range []string{"", ":443"} {
			rs := m{"privateKey": priv, "shortIds": []string{"ab"}, "settings": m{"fingerprint": "chrome"}}
			if sni != "" {
				rs["serverNames"] = []string{sni}
			}
			if target != "" {
				rs["target"] = target
			}
			d, p := realXUI(t)
			addInbound(t, d, "r", 443, "vless", `{"clients":[]}`, jsonOf(t, m{"network": "tcp", "security": "reality", "realitySettings": rs}))
			data, err := Read3XUI(p)
			if err != nil {
				t.Fatal(err)
			}
			if in := data.Inbounds[0]; in.Kind != "" || in.SkipReason == "" {
				t.Errorf("sni=%q target=%q: подключение не пропущено (kind=%q)", sni, target, in.Kind)
			}
		}
	}
}

func TestEmptyTargetWarns(t *testing.T) {
	priv, _, _ := proto.RealityKeys()
	d, p := realXUI(t)
	addInbound(t, d, "r", 443, "vless", `{"clients":[]}`, jsonOf(t, m{"network": "tcp", "security": "reality", "realitySettings": m{
		"serverNames": []string{"www.example.com"}, "privateKey": priv, "shortIds": []string{"ab"}, "settings": m{"fingerprint": "chrome"}}}))
	data, err := Read3XUI(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(data.Inbounds[0].Warnings, "|"), "не задан") {
		t.Errorf("нет предупреждения о пустом target: %v", data.Inbounds[0].Warnings)
	}
}

func TestCleanTempSkipsFresh(t *testing.T) {
	t.Chdir(t.TempDir())
	old := CleanTempMinAge
	defer func() { CleanTempMinAge = old }()
	CleanTempMinAge = time.Hour
	root, _ := TempRoot()
	fresh, stale := filepath.Join(root, "kitsune-import-fresh"), filepath.Join(root, "kitsune-upload-stale")
	_ = os.MkdirAll(fresh, 0o700)
	_ = os.MkdirAll(stale, 0o700)
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, past, past); err != nil {
		t.Fatal(err)
	}
	CleanTemp()
	if _, err := os.Stat(fresh); err != nil {
		t.Error("свежая папка удалена")
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("старая папка не убрана")
	}
}
