package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const latestReleaseAPI = "https://api.github.com/repos/itsnotkubrick/Kitsune/releases/latest"
const githubTokenFile = "/etc/kitsune/github-token"

var stableTag = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+$`)

// CheckRelease checks GitHub Latest, or VERSION at an explicitly configured mirror.
func CheckRelease(baseURL, current string) (*Info, error) {
	var raw string
	var err error
	if baseURL != "" {
		raw, err = versionViaHTTP(baseURL)
	} else {
		token := strings.TrimSpace(os.Getenv("KITSUNE_TOKEN"))
		if token == "" {
			data, readErr := os.ReadFile(githubTokenFile)
			if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
				return nil, fmt.Errorf("не удалось прочитать %s: %w", githubTokenFile, readErr)
			}
			token = strings.TrimSpace(string(data))
		}
		raw, err = versionViaGitHub(latestReleaseAPI, token)
	}
	if err != nil {
		return nil, err
	}
	latest := strings.TrimSpace(strings.SplitN(raw, "\n", 2)[0])
	if latest == "" || len(latest) > 40 {
		return nil, errors.New("в релизе нет корректной версии")
	}
	return &Info{Current: current, Latest: latest, Available: Newer(latest, current)}, nil
}

func versionViaGitHub(endpoint, token string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("не удалось проверить GitHub Releases: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub Latest недоступен (HTTP %d); для закрытого репозитория проверьте токен в %s", resp.StatusCode, githubTokenFile)
	}
	var release struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Assets     []struct {
			Name string `json:"name"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&release); err != nil {
		return "", fmt.Errorf("некорректный ответ GitHub Releases: %w", err)
	}
	if release.Draft || release.Prerelease || !stableTag.MatchString(release.Tag) {
		return "", errors.New("GitHub Latest не содержит корректной стабильной версии")
	}
	assets := make(map[string]bool, len(release.Assets))
	for _, asset := range release.Assets {
		assets[asset.Name] = true
	}
	for _, name := range []string{"install.sh", "SHA256SUMS", "SHA256SUMS.sig", "kitsune-linux-amd64", "kitsune-linux-arm64"} {
		if !assets[name] {
			return "", fmt.Errorf("в релизе %s отсутствует %s", release.Tag, name)
		}
	}
	return strings.TrimPrefix(release.Tag, "v"), nil
}

func versionViaHTTP(baseURL string) (string, error) {
	if err := checkURL(baseURL); err != nil {
		return "", err
	}
	c := &http.Client{Timeout: 15 * time.Second}
	resp, err := c.Get(strings.TrimRight(baseURL, "/") + "/VERSION")
	if err != nil {
		return "", fmt.Errorf("не удалось проверить обновления: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", errors.New("релиз недоступен (ответ 404): проверьте адрес обновлений или обновите вручную командой kit update ФАЙЛ")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("сервер обновлений ответил %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return string(b), err
}
