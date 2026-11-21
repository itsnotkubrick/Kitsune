package main

import (
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"kitsune/internal/db"
)

// csrfGuard не пускает изменяющие запросы с чужих страниц. SameSite=Lax не считается единственной защитой:
// он не спасает от соседних поддоменов того же сайта, а форма text/plain может отправить JSON без предварительного запроса.
// Проверяем Origin (или Referer), а у запросов с телом ещё и Content-Type. Запросы без этих заголовков (curl, скрипты) пропускаем:
// браузер их всегда ставит, а доступ без куки сессии всё равно закрыт.
func csrfGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}
		if !sameOriginRequest(c) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Запрос с другого сайта отклонён"})
			return
		}
		if c.Request.ContentLength != 0 && !bodyTypeAllowed(c.GetHeader("Content-Type")) {
			c.AbortWithStatusJSON(http.StatusUnsupportedMediaType, gin.H{"error": "Тело запроса должно быть JSON"})
			return
		}
		c.Next()
	}
}

func bodyTypeAllowed(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == "application/json" || mt == "multipart/form-data"
}

// sameOriginRequest: Origin (иначе Referer) должен указывать на этот же адрес. Без обоих заголовков решает Sec-Fetch-Site.
func sameOriginRequest(c *gin.Context) bool {
	if o := c.GetHeader("Origin"); o != "" {
		return hostAllowed(c, o)
	}
	if r := c.GetHeader("Referer"); r != "" {
		return hostAllowed(c, r)
	}
	switch c.GetHeader("Sec-Fetch-Site") {
	case "cross-site", "same-site":
		return false
	}
	return true
}

func hostAllowed(c *gin.Context, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false // в том числе Origin: null
	}
	scheme := "http"
	if isSecureRequest(c) {
		scheme = "https"
	}
	return u.Scheme == scheme && strings.EqualFold(u.Host, requestHost(c.Request))
}

func requestHost(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-Host"); forwarded != "" && trustedProxy(r.RemoteAddr) {
		return forwarded
	}
	return r.Host
}

func isSecureRequest(c *gin.Context) bool {
	return isSecureHTTP(c.Request)
}

func isSecureHTTP(r *http.Request) bool {
	return r.TLS != nil || (strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") && trustedProxy(r.RemoteAddr))
}

// validHostName: адрес сервера, который можно запомнить (IP или домен), без служебных символов из заголовка Host.
func validHostName(h string) bool {
	if net.ParseIP(h) != nil {
		return true
	}
	return domainRe.MatchString(strings.ToLower(h))
}

// validateCustomCert проверяет файлы своего сертификата до того, как их прочитает root-процесс:
// только обычные файлы разумного размера по чистому абсолютному пути, не из системных каталогов устройств.
func validateCustomCert(certFile, keyFile string) error {
	for _, p := range []string{certFile, keyFile} {
		if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fmt.Errorf("укажите полный путь к файлу без «..»")
		}
		for _, bad := range []string{"/proc/", "/sys/", "/dev/", "/run/"} {
			if strings.HasPrefix(p+"/", bad) || strings.HasPrefix(p, bad) {
				return fmt.Errorf("файл %s лежит в системном каталоге", p)
			}
		}
		st, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("файл %s не найден", p)
		}
		if !st.Mode().IsRegular() || st.Size() == 0 || st.Size() > 1<<20 {
			return fmt.Errorf("%s: это должен быть обычный файл размером до 1 МБ", p)
		}
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return fmt.Errorf("сертификат не загружается: %v", err)
	}
	return nil
}

func sessionEpoch() string {
	return db.GetSetting("session_epoch", "0")
}
