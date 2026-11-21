// Package totp – одноразовые коды (RFC 6238: HMAC-SHA1, 30 секунд, 6 цифр) для двухфакторного входа.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	Period = 30
	Digits = 6
)

var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret создаёт секрет (160 бит) в base32.
func NewSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return enc.EncodeToString(b), nil
}

func code(secret string, step uint64) (string, error) {
	key, err := enc.DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], step)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (uint32(sum[off]&0x7f) << 24) | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%0*d", Digits, v%1000000), nil
}

// Step – номер 30-секундного интервала для момента t.
func Step(t time.Time) uint64 { return uint64(t.Unix() / Period) }

// Verify проверяет код с допуском ±1 интервал (часы на телефоне и сервере расходятся). Возвращает интервал, в который
// код подошёл: сохраняя его, можно запретить повторное использование того же кода.
func Verify(secret, input string, now time.Time) (uint64, bool) {
	input = strings.ReplaceAll(strings.TrimSpace(input), " ", "")
	if len(input) != Digits {
		return 0, false
	}
	cur := Step(now)
	for _, s := range []uint64{cur - 1, cur, cur + 1} {
		want, err := code(secret, s)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(input)) == 1 {
			return s, true
		}
	}
	return 0, false
}

// Code – текущий код (для тестов и проверки).
func Code(secret string, t time.Time) (string, error) { return code(secret, Step(t)) }

// URI – ссылка otpauth:// для QR-кода приложения-аутентификатора.
func URI(secret, account, issuer string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}
