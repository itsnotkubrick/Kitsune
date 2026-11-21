// Package security – проверки безопасности паролей.
package security

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// PwnedAPI – служба Have I Been Pwned (Pwned Passwords). Используется модель k-anonymity: наружу уходят только
// первые 5 символов SHA-1 пароля, сам пароль и его полный хеш с сервера не покидают.
var PwnedAPI = "https://api.pwnedpasswords.com"

func init() {
	if v := os.Getenv("KITSUNE_PWNED_API"); v != "" {
		PwnedAPI = v
	}
}

// Pwned возвращает, сколько раз пароль встречался в известных утечках. Ошибка сети – не повод блокировать смену пароля.
func Pwned(password string) (int, error) {
	sum := sha1.Sum([]byte(password))
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	req, _ := http.NewRequest("GET", strings.TrimRight(PwnedAPI, "/")+"/range/"+h[:5], nil)
	req.Header.Set("Add-Padding", "true")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("служба проверки ответила %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], h[5:]) {
			n, _ := strconv.Atoi(parts[1])
			return n, nil // записи с нулём – «подкладка» ответа, они означают «не найден»
		}
	}
	return 0, nil
}
