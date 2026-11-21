// Package release готовит релиз панели: ключи подписи, сборки под платформы и подписанный манифест latest.json.
package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"kitsune/internal/update"
)

// Platforms – сборки релиза.
var Platforms = []string{"linux-amd64", "linux-arm64", "darwin-arm64"}

// GenerateKey создаёт пару ed25519. Закрытый ключ – seed в base64 (32 байта), открытый – base64.
func GenerateKey() (priv, pub string, err error) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(sk.Seed()), base64.StdEncoding.EncodeToString(pk), nil
}

func privateFromSeed(seedB64 string) (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(seedB64))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("закрытый ключ должен быть base64 от 32 байт")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// PublicFromSeed возвращает открытый ключ для закрытого.
func PublicFromSeed(seedB64 string) (string, error) {
	sk, err := privateFromSeed(seedB64)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sk.Public().(ed25519.PublicKey)), nil
}

// Sign подписывает SHA-256 сборки (hex, нижний регистр) – ровно то, что проверяет панель при обновлении.
func Sign(seedB64, sha256hex string) (string, error) {
	sk, err := privateFromSeed(seedB64)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(sk, []byte(strings.ToLower(strings.TrimSpace(sha256hex))))), nil
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

type Options struct {
	Version     string
	Repo        string // владелец/репозиторий на GitHub
	SeedB64     string
	OutDir      string
	Notes       string
	Platforms   []string
	ManifestURL string // зашивается в бинарник (пусто – вычисляется из Repo)
}

// BuildManifest подписывает готовые файлы из каталога out и собирает манифест.
func BuildManifest(o Options, files map[string]string) (*update.Manifest, error) {
	pub, err := PublicFromSeed(o.SeedB64)
	if err != nil {
		return nil, err
	}
	base := fmt.Sprintf("https://github.com/%s/releases/download/v%s", o.Repo, o.Version)
	m := &update.Manifest{Version: o.Version, Notes: o.Notes, Assets: map[string]update.Asset{}}
	plats := make([]string, 0, len(files))
	for p := range files {
		plats = append(plats, p)
	}
	sort.Strings(plats)
	for _, plat := range plats {
		sum, err := fileSHA256(files[plat])
		if err != nil {
			return nil, err
		}
		sig, err := Sign(o.SeedB64, sum)
		if err != nil {
			return nil, err
		}
		a := update.Asset{URL: base + "/" + filepath.Base(files[plat]), SHA256: sum, Sig: sig}
		if err := update.VerifyAsset(pub, a); err != nil { // самопроверка: подпись обязана проходить проверку панели
			return nil, fmt.Errorf("самопроверка подписи %s: %w", plat, err)
		}
		m.Assets[plat] = a
	}
	return m, nil
}

// Build собирает бинарники под платформы с зашитыми версией, ключом и адресом манифеста и пишет latest.json.
func Build(o Options) (*update.Manifest, error) {
	pub, err := PublicFromSeed(o.SeedB64)
	if err != nil {
		return nil, err
	}
	if o.ManifestURL == "" {
		o.ManifestURL = fmt.Sprintf("https://github.com/%s/releases/latest/download/latest.json", o.Repo)
	}
	if err := os.MkdirAll(o.OutDir, 0o755); err != nil {
		return nil, err
	}
	ld := fmt.Sprintf("-s -w -X kitsune/internal/version.Version=%s -X kitsune/internal/update.PublicKey=%s -X kitsune/internal/update.ManifestURL=%s", o.Version, pub, o.ManifestURL)
	files := map[string]string{}
	plats := o.Platforms
	if len(plats) == 0 {
		plats = Platforms
	}
	for _, plat := range plats {
		parts := strings.SplitN(plat, "-", 2)
		out := filepath.Join(o.OutDir, "kitsune-"+plat)
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags", ld, "-o", out, "./cmd/server")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+parts[0], "GOARCH="+parts[1])
		if outb, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("сборка %s: %v\n%s", plat, err, outb)
		}
		files[plat] = out
	}
	m, err := BuildManifest(o, files)
	if err != nil {
		return nil, err
	}
	data, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(o.OutDir, "latest.json"), data, 0o644); err != nil {
		return nil, err
	}
	return m, nil
}
