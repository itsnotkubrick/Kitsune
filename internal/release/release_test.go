package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kitsune/internal/update"
)

func TestSignVerifyRoundTripAndTamper(t *testing.T) {
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if p2, _ := PublicFromSeed(priv); p2 != pub {
		t.Fatal("открытый ключ из закрытого не совпал")
	}
	sum := strings.Repeat("ab", 32)
	sig, _ := Sign(priv, sum)
	a := update.Asset{URL: "https://x/y", SHA256: sum, Sig: sig}
	if err := update.VerifyAsset(pub, a); err != nil {
		t.Fatalf("настоящая подпись не прошла: %v", err)
	}
	a.SHA256 = strings.Repeat("cd", 32) // подмена файла
	if err := update.VerifyAsset(pub, a); err == nil {
		t.Fatal("подпись под другой суммой должна отклоняться")
	}
	_, other, _ := GenerateKey()
	a.SHA256 = sum
	if err := update.VerifyAsset(other, a); err == nil {
		t.Fatal("чужой ключ должен отклоняться")
	}
	if err := update.VerifyAsset(pub, update.Asset{SHA256: sum}); err == nil {
		t.Fatal("релиз без подписи должен отклоняться, когда ключ задан")
	}
}

func TestBuildManifestSignsEveryFile(t *testing.T) {
	priv, pub, _ := GenerateKey()
	dir := t.TempDir()
	files := map[string]string{}
	for _, p := range []string{"linux-amd64", "linux-arm64"} {
		f := filepath.Join(dir, "kitsune-"+p)
		_ = os.WriteFile(f, []byte("binary-"+p), 0o755)
		files[p] = f
	}
	m, err := BuildManifest(Options{Version: "0.2", Repo: "me/Kitsune", SeedB64: priv}, files)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Assets) != 2 || !strings.HasPrefix(m.Assets["linux-amd64"].URL, "https://github.com/me/Kitsune/releases/download/v0.2/kitsune-") {
		t.Fatalf("%+v", m)
	}
	for p, a := range m.Assets {
		if err := update.VerifyAsset(pub, a); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
}
