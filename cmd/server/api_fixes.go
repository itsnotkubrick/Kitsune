package main

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"kitsune/internal/acme"
	"kitsune/internal/check"
	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/proto"
)

// Исправления «Паспорта безопасности»: они меняют настройки панели, поэтому живут здесь, а не в пакете проверок.

func init() {
	check.FixHooks["sni"] = fixSNI
	check.FixHooks["panelpath"] = fixPanelPath
	check.FixHooks["certs"] = fixCerts
}

// pickSNI выбирает первый сайт из списка, который подходит (кроме текущего).
func pickSNI(candidates []string, current string, ok func(string) bool) string {
	for _, c := range candidates {
		if c != current && ok(c) {
			return c
		}
	}
	return ""
}

// fixSNI меняет сайт-прикрытие одного подключения REALITY на рабочий из списка. Старое имя ещё 7 дней принимается.
func fixSNI(arg string) (string, error) {
	id, err := strconv.Atoi(arg)
	if err != nil {
		return "", errors.New("не указано подключение")
	}
	var found *db.Inbound
	inbounds, _ := db.GetInbounds()
	for i := range inbounds {
		if inbounds[i].ID == id {
			found = &inbounds[i]
		}
	}
	if found == nil || found.Kind != string(proto.VlessReality) {
		return "", errors.New("подключение не найдено или не REALITY")
	}
	s := proto.ParseSettings(found.Settings)
	old := s.SNI
	sni := pickSNI(proto.DefaultSNIs, old, sniWorks)
	if sni == "" {
		return "", errors.New("с этого сервера не нашлось подходящего сайта (TLS 1.3 и HTTP/2); проверьте сеть сервера")
	}
	s.SNI, s.Target = sni, ""
	s.WithOldSNI(old, time.Now().Add(7*24*time.Hour).Unix())
	if _, err := db.DB.Exec("UPDATE inbounds SET sni = ?, settings = ? WHERE id = ?", sni, s.JSON(), found.ID); err != nil {
		return "", err
	}
	if err := applyCores(); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s: сайт-прикрытие %s → %s. Клиенты получат новые ссылки при обновлении подписки, старые работают 7 дней", found.Tag, old, sni), nil
}

var lastPanelPath string

// fixPanelPath задаёт секретный путь входа. После этого панель открывается только по нему.
func fixPanelPath(string) (string, error) {
	if panelPath() != "" {
		return "Секретный путь уже задан", nil
	}
	p := db.RandomSlug(10)
	if err := db.SetSetting("panel_path", p); err != nil {
		return "", err
	}
	lastPanelPath = p
	return "Секретный путь входа задан: /" + p + "/ (сохраните новый адрес панели)", nil
}

// afterFix дополняет результат исправления тем, что нужно знать текущему браузеру: без пропуска панель сразу перестала бы открываться.
func afterFix(c *gin.Context, code string, msg string) string {
	if code != "panelpath" || lastPanelPath == "" {
		return msg
	}
	secure := isSecureRequest(c)
	http.SetCookie(c.Writer, &http.Cookie{Name: gateCookie, Value: gateValue(), Path: "/", MaxAge: 86400 * 30, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
	scheme := "http"
	if secure {
		scheme = "https"
	}
	url := scheme + "://" + c.Request.Host + "/" + lastPanelPath + "/"
	lastPanelPath = ""
	return msg + ". Новый адрес: " + url
}

// acmeFiles – получение сертификата домена; в тестах подменяется.
var acmeFiles = acme.Files

// tlsInboundKind – подключения, которым нужен сертификат на домен.
func tlsInboundKind(k string) bool {
	switch proto.Kind(k) {
	case proto.VlessWS, proto.VmessWS, proto.TrojanGRPC, proto.Hysteria2, proto.TUIC, proto.Naive:
		return true
	}
	return false
}

// fixCerts переводит подключения с самоподписанным сертификатом на сертификат Let's Encrypt домена панели.
// Работает только если Let's Encrypt для домена панели уже включён: сертификат берётся тот же, поэтому ничего не ломается.
// Сначала проверяем, что сертификат получен, и только потом меняем настройки.
func fixCerts(string) (string, error) {
	t := core.LoadPanelTLS()
	domain := strings.ToLower(strings.TrimSpace(t.Domain))
	if t.Mode != "acme" || domain == "" {
		return "", errors.New("сначала включите Let's Encrypt для домена панели: «Настройки → Сеть и сертификаты»")
	}
	if err := core.ConfigureACME(); err != nil {
		return "", err
	}
	if _, _, _, err := acmeFiles(domain); err != nil {
		return "", fmt.Errorf("сертификат для %s не получен, подключения не менялись: %w", domain, err)
	}
	inbounds, err := db.GetInbounds()
	if err != nil {
		return "", err
	}
	var changed []string
	for _, ib := range inbounds {
		if !tlsInboundKind(ib.Kind) {
			continue
		}
		st := proto.ParseSettings(ib.Settings)
		if st.CertMode == "custom" || st.CertMode == "acme" {
			continue
		}
		st.SNI, st.CertMode = domain, "acme"
		if _, err := db.DB.Exec("UPDATE inbounds SET sni = ?, settings = ? WHERE id = ?", domain, st.JSON(), ib.ID); err != nil {
			return "", err
		}
		changed = append(changed, ib.Tag)
	}
	if len(changed) == 0 {
		return "Все подключения уже с настоящим сертификатом", nil
	}
	if err := applyCores(); err != nil {
		return "", fmt.Errorf("настройки сохранены, но ядро не приняло конфиг: %w", err)
	}
	return fmt.Sprintf("Подключения %s теперь используют сертификат Let's Encrypt для %s. Клиенты получат новые ссылки при обновлении подписки", strings.Join(changed, ", "), domain), nil
}
