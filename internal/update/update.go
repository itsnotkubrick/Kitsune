// Package update обновляет панель Kitsune из манифеста релиза: скачивает бинарник, проверяет SHA-256
// (и подпись ed25519, если задан публичный ключ), заменяет себя и перезапускается.
//
// Формат манифеста (JSON по адресу из настроек):
//
//	{
//	  "version": "1.9.0",
//	  "notes": "Что нового",
//	  "assets": {
//	    "linux-amd64": {"url": "https://…/kitsune-linux-amd64", "sha256": "…hex…", "sig": "…base64 ed25519 от sha256-hex…"}
//	  }
//	}
package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Asset struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Sig    string `json:"sig,omitempty"`
}

type Manifest struct {
	Version string           `json:"version"`
	Notes   string           `json:"notes"`
	Assets  map[string]Asset `json:"assets"`
}

type Info struct {
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Available bool   `json:"available"`
	Notes     string `json:"notes"`
	Signed    bool   `json:"signed"` // проверяется ли подпись
}

// Официальный источник обновлений Kitsune. ManifestURL можно переопределить переменной окружения
// KITSUNE_UPDATE_URL (для разработки и тестов), в интерфейсе панели адрес не меняется.
// PublicKey – ed25519-ключ издателя (base64): если задан, релизы без валидной подписи отклоняются.
var (
	ManifestURL = "https://raw.githubusercontent.com/itsnotkubrick/Kitsune/main/latest.json"
	PublicKey   = ""
)

// Source возвращает адрес манифеста и публичный ключ с учётом переопределения из окружения.
func Source() (manifestURL, pubKey string) {
	manifestURL = ManifestURL
	if v := os.Getenv("KITSUNE_UPDATE_URL"); v != "" {
		manifestURL = v
	}
	return manifestURL, PublicKey
}

const maxBinary = 200 << 20

var client = &http.Client{Timeout: 5 * time.Minute}

func platform() string { return runtime.GOOS + "-" + runtime.GOARCH }

// checkURL допускает только https (и http для localhost при разработке).
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("некорректный адрес обновлений")
	}
	if u.Scheme == "https" {
		return nil
	}
	h := u.Hostname()
	if u.Scheme == "http" && (h == "localhost" || h == "127.0.0.1" || h == "::1") {
		return nil
	}
	return errors.New("адрес обновлений должен начинаться с https://")
}

func fetchManifest(manifestURL string) (*Manifest, error) {
	if err := checkURL(manifestURL); err != nil {
		return nil, err
	}
	resp, err := client.Get(manifestURL)
	if err != nil {
		return nil, fmt.Errorf("не удалось получить манифест: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("сервер обновлений ответил %d", resp.StatusCode)
	}
	var m Manifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		return nil, fmt.Errorf("манифест не разобран: %w", err)
	}
	if m.Version == "" {
		return nil, errors.New("в манифесте нет версии")
	}
	return &m, nil
}

// Newer: a новее b (версии вида 1.9.0, префикс v допускается). При равных числах пре-релиз (суффикс -pre…) старше релиза.
func Newer(a, b string) bool {
	pa, pb := parse(a), parse(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	if ba, bb := build(a), build(b); ba != bb {
		return ba > bb
	}
	return isPre(b) && !isPre(a)
}

// build – номер сборки в конце суффикса: «0.1-test.7» → 7 (между тестовыми выпусками с одним номером версии).
func build(v string) int {
	v = strings.TrimSpace(v)
	i := strings.Index(v, "-")
	if i < 0 {
		return 0
	}
	n, mul := 0, 1
	digits := false
	for j := len(v) - 1; j > i; j-- {
		c := v[j]
		if c < '0' || c > '9' {
			break
		}
		n += int(c-'0') * mul
		mul *= 10
		digits = true
	}
	if !digits {
		return 0
	}
	return n
}

func isPre(v string) bool { return strings.Contains(strings.TrimSpace(v), "-pre") }

func parse(v string) [3]int {
	var r [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	for i, p := range strings.SplitN(v, ".", 3) {
		digits := ""
		for _, c := range p {
			if c < '0' || c > '9' {
				break
			}
			digits += string(c)
		}
		r[i], _ = strconv.Atoi(digits)
	}
	return r
}

// Check сверяет текущую версию с манифестом.
func Check(manifestURL, current, pubKeyB64 string) (*Info, error) {
	m, err := fetchManifest(manifestURL)
	if err != nil {
		return nil, err
	}
	return &Info{Current: current, Latest: m.Version, Available: Newer(m.Version, current), Notes: m.Notes, Signed: pubKeyB64 != ""}, nil
}

// Apply скачивает и ставит новую версию. После успеха планирует перезапуск и возвращается.
func Apply(manifestURL, current, pubKeyB64 string) (string, error) {
	m, err := fetchManifest(manifestURL)
	if err != nil {
		return "", err
	}
	if !Newer(m.Version, current) {
		return "", errors.New("установлена последняя версия")
	}
	a, ok := m.Assets[platform()]
	if !ok {
		return "", fmt.Errorf("в релизе %s нет сборки для %s", m.Version, platform())
	}
	if err := checkURL(a.URL); err != nil {
		return "", err
	}
	want, err := hex.DecodeString(strings.TrimSpace(a.SHA256))
	if err != nil || len(want) != sha256.Size {
		return "", errors.New("в манифесте нет корректной суммы SHA-256")
	}
	if pubKeyB64 != "" {
		if err := verifySig(pubKeyB64, a); err != nil {
			return "", err
		}
	}

	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	self, _ = filepath.EvalSymlinks(self)
	dir := filepath.Dir(self)
	tmp, err := os.CreateTemp(dir, ".kitsune-new-*")
	if err != nil {
		return "", fmt.Errorf("нет прав на запись в %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	resp, err := client.Get(a.URL)
	if err != nil {
		tmp.Close()
		return "", fmt.Errorf("загрузка не удалась: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		tmp.Close()
		return "", fmt.Errorf("сервер загрузки ответил %d", resp.StatusCode)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, maxBinary+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if n > maxBinary {
		return "", errors.New("файл обновления слишком большой")
	}
	if hex.EncodeToString(h.Sum(nil)) != hex.EncodeToString(want) {
		return "", errors.New("контрольная сумма не совпала – обновление отклонено")
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return "", err
	}

	// Старую версию оставляем рядом на случай отката.
	old := self + ".old"
	_ = os.Remove(old)
	if err := os.Rename(self, old); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, self); err != nil {
		_ = os.Rename(old, self)
		return "", err
	}

	go restart(self)
	return m.Version, nil
}

// VerifyAsset проверяет подпись ed25519 над SHA-256 сборки (используется и инструментом выпуска для самопроверки).
func VerifyAsset(pubB64 string, a Asset) error { return verifySig(pubB64, a) }

func verifySig(pubB64 string, a Asset) error {
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("публичный ключ подписи в настройках задан неверно")
	}
	sig, err := base64.StdEncoding.DecodeString(a.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("у релиза нет корректной подписи – обновление отклонено")
	}
	if !ed25519.Verify(pub, []byte(strings.ToLower(strings.TrimSpace(a.SHA256))), sig) {
		return errors.New("подпись релиза не прошла проверку – обновление отклонено")
	}
	return nil
}

// restart: через systemd, если панель запущена как служба kitsune, иначе – повторный запуск процесса.
func restart(self string) {
	time.Sleep(1500 * time.Millisecond) // дать ответу API уйти
	if runtime.GOOS == "linux" {
		if out, _ := exec.Command("systemctl", "is-active", "kitsune").Output(); strings.TrimSpace(string(out)) == "active" {
			if exec.Command("systemctl", "restart", "kitsune").Run() == nil {
				return
			}
		}
	}
	_ = syscall.Exec(self, os.Args, os.Environ())
}
