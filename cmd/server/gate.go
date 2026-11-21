package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"kitsune/internal/site"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
	"kitsune/web"
)

// Внутренний адрес панели в режиме «только через SSH-туннель»: наружу он не открывается.
const adminLoopback = "127.0.0.1:10380"

const gateCookie = "pref"

// sessionCookie – имя cookie сессии панели: нейтральное, без названия продукта.
const sessionCookie = "sid"

var pathRe = regexp.MustCompile(`^[a-z0-9]{6,32}$`)

// panelPath – секретный путь панели (пусто – выключен).
func panelPath() string {
	p := strings.Trim(db.GetSetting("panel_path", ""), "/")
	if pathRe.MatchString(p) {
		return p
	}
	return ""
}

func panelPrivate() bool { return db.GetSetting("panel_private", "") == "1" }

func gateValue() string {
	m := hmac.New(sha256.New, sessionSecret())
	m.Write([]byte("kitsune-gate"))
	return hex.EncodeToString(m.Sum(nil))
}

func remoteIsLoopback(r *http.Request) bool {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// onAdminLoopback: запрос пришёл на внутренний адрес панели (то есть через SSH-туннель).
func onAdminLoopback(r *http.Request) bool {
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		return a.String() == adminLoopback
	}
	return false
}

func notFound(c *gin.Context) {
	writeNotFound(c.Writer)
	c.Abort()
}

// writeNotFound – единый ответ 404 для всех режимов: те же код, заголовки и тело. Заголовки панели (X-Frame-Options, CSP и
// другие) на нём не нужны и были бы отдельной приметой: у nginx их на 404 нет.
func writeNotFound(w http.ResponseWriter) {
	h := w.Header()
	for _, k := range []string{"X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "Cache-Control", "Pragma"} {
		h.Del(k)
	}
	h.Set("Server", "nginx")
	h.Set("Content-Type", "text/html")
	h.Set("Content-Length", strconv.Itoa(len(site.NotFoundBody)))
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(site.NotFoundBody))
}

// setupNotFound делает все неизвестные адреса и методы неотличимыми: один ответ notFound, без редиректов на «слэш».
func setupNotFound(r *gin.Engine) {
	r.RedirectTrailingSlash = false
	r.RedirectFixedPath = false
	r.HandleMethodNotAllowed = false
	r.NoRoute(notFound)
}

// gateMiddleware прячет панель за секретным путём: без него любой адрес, кроме подписок, отвечает 404.
// Вход по /секретный-путь/ выдаёт «пропуск» (куки), с которым работает остальное; страницы входа и API без него не видны.
func gateMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		p := panelPath()
		path := c.Request.URL.Path
		if p == "" || strings.HasPrefix(path, "/sub/") || onAdminLoopback(c.Request) {
			c.Next()
			return
		}
		if path == "/api/health" && remoteIsLoopback(c.Request) { // проверка живости самим сервером
			c.Next()
			return
		}
		if path == "/"+p || path == "/"+p+"/" {
			secure := isSecureRequest(c)
			http.SetCookie(c.Writer, &http.Cookie{Name: gateCookie, Value: gateValue(), Path: "/", MaxAge: 86400 * 30, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
			c.Header("Cache-Control", "no-store")
			c.Data(http.StatusOK, "text/html; charset=utf-8", web.IndexHTML)
			c.Abort()
			return
		}
		if ck, err := c.Request.Cookie(gateCookie); err == nil && hmac.Equal([]byte(ck.Value), []byte(gateValue())) {
			c.Next()
			return
		}
		notFound(c)
	}
}

// subOnly оставляет на публичных портах только подписки (режим «панель только через SSH-туннель»).
func subOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/sub/") || (r.URL.Path == "/api/health" && remoteIsLoopback(r)) {
			next.ServeHTTP(w, r)
			return
		}
		writeNotFound(w)
	})
}
