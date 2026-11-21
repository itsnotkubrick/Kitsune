package main

import (
	"database/sql"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
	"kitsune/internal/sub"
)

const connectCSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"

// connectUser ищет владельца ссылки с теми же защитами, что и у самой подписки: лимит неудачных попыток и обычный 404.
func connectUser(c *gin.Context) (*db.User, bool) {
	ip := c.ClientIP()
	if subBlocked(ip) {
		notFound(c)
		return nil, false
	}
	u, err := db.GetUserBySubID(c.Param("subid"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			subFail(ip)
		}
		notFound(c)
		return nil, false
	}
	return u, true
}

// handleConnectPage – страница «Подключить за пару минут»: открывается по ссылке подписки + /connect.
func handleConnectPage(c *gin.Context) {
	u, ok := connectUser(c)
	if !ok {
		return
	}
	plat := sub.ConnectPlatform(c.GetHeader("User-Agent"))
	if c.Request.Method != http.MethodHead {
		_ = db.MarkConnect(u.ID, db.EvPage, plat)
	}
	c.Header("Cache-Control", "no-store")
	c.Header("X-Frame-Options", "DENY")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Content-Security-Policy", connectCSP)
	c.Data(http.StatusOK, "text/html; charset=utf-8", sub.ConnectPage(*u, subBase(c)+"/sub/"+u.SubID, plat))
}

// handleConnectEvent запоминает шаг, который человек сделал на странице (открыл магазин, нажал «Добавить»).
func handleConnectEvent(c *gin.Context) {
	u, ok := connectUser(c)
	if !ok {
		return
	}
	switch ev := c.Param("event"); ev {
	case db.EvStore, db.EvAdd:
		_ = db.MarkConnect(u.ID, ev, "")
		c.Status(http.StatusNoContent)
	default:
		notFound(c)
	}
}

var appUA = []struct {
	re   *regexp.Regexp
	name string
}{
	{regexp.MustCompile("(?i)happ"), "Happ"},
	{regexp.MustCompile("(?i)hiddify"), "Hiddify"},
	{regexp.MustCompile("(?i)karing"), "Karing"},
	{regexp.MustCompile("(?i)v2rayng"), "v2rayNG"},
	{regexp.MustCompile("(?i)streisand"), "Streisand"},
	{regexp.MustCompile("(?i)sing-?box|sfa|sfi"), "sing-box"},
	{regexp.MustCompile("(?i)clash|mihomo|stash"), "Clash"},
}

// appFromUA – короткое название приложения по User-Agent.
func appFromUA(ua string) string {
	for _, a := range appUA {
		if a.re.MatchString(ua) {
			return a.name
		}
	}
	if i := strings.IndexAny(ua, "/ "); i > 0 {
		return ua[:i]
	}
	return ua
}

type progressStep struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Done  bool   `json:"done"`
	At    int64  `json:"at,omitempty"`
	Note  string `json:"note,omitempty"`
}

// connectProgress – этапы подключения человека: от открытия страницы до реального трафика.
func connectProgress(u db.User) []progressStep {
	ev := db.GetConnect(u.ID)
	mk := func(key, label, evKey string) progressStep {
		e, ok := ev[evKey]
		return progressStep{Key: key, Label: label, Done: ok, At: e.At, Note: e.Extra}
	}
	steps := []progressStep{
		mk("page", "Открыл страницу подключения", db.EvPage),
		mk("store", "Пошёл за приложением", db.EvStore),
		mk("add", "Нажал «Добавить»", db.EvAdd),
		mk("sub", "Приложение получило подписку", db.EvSub),
	}
	steps = append(steps, progressStep{Key: "traffic", Label: "VPN подключался (был трафик)", Done: u.UsedTraffic > 0})
	return steps
}
