package main

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"kitsune/internal/db"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// Сессия панели живёт, пока в ней есть запросы: если вкладку закрыли и не возвращались дольше срока бездействия,
// следующий запрос получит 401 и потребуется войти снова. Открытая вкладка сама опрашивает сервер раз в 10 секунд и
// сессию поддерживает; закрытая вкладка, спящий ноутбук и забытый браузер её не поддерживают.
const (
	sessionIdleDefault = 30 * time.Minute
	sessionIdleMin     = 5 * time.Minute
	sessionIdleMax     = 24 * time.Hour
	sessionMaxAge      = 12 * time.Hour // абсолютный срок: после него вход нужен независимо от активности
	sessionTouchEvery  = time.Minute    // чаще метку в cookie не переписываем: опросы идут каждые 10 секунд
)

var sessionNow = time.Now

// sessionIdle – срок бездействия. Настройка session_idle_minutes (5..1440 минут), по умолчанию 30.
func sessionIdle() time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(db.GetSetting("session_idle_minutes", "")))
	if err != nil {
		return sessionIdleDefault
	}
	d := time.Duration(n) * time.Minute
	if d < sessionIdleMin {
		return sessionIdleMin
	}
	if d > sessionIdleMax {
		return sessionIdleMax
	}
	return d
}

func sessionInt(v any) (int64, bool) {
	n, ok := v.(int64)
	return n, ok
}

// sessionExpired: нет меток времени (сессия выдана до этой проверки), превышен срок бездействия или абсолютный срок.
func sessionExpired(loginAt, lastSeen any, now time.Time, idle time.Duration) bool {
	l, ok1 := sessionInt(loginAt)
	s, ok2 := sessionInt(lastSeen)
	if !ok1 || !ok2 {
		return true
	}
	t := now.Unix()
	return t-s > int64(idle/time.Second) || t-l > int64(sessionMaxAge/time.Second) || s > t+60 || l > t+60
}

// startSession запоминает вход: время входа и время последней активности.
func startSession(session sessions.Session, username string, secure bool) {
	now := sessionNow().Unix()
	session.Options(sessions.Options{Path: "/", MaxAge: int(sessionMaxAge / time.Second), HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
	session.Set("username", username)
	session.Set("epoch", sessionEpoch())
	session.Set("login_at", now)
	session.Set("last_seen", now)
	_ = session.Save()
}

// checkSession проверяет срок и продлевает окно бездействия. Возвращает false, если сессия истекла (она уже очищена).
func checkSession(c *gin.Context, session sessions.Session) bool {
	now := sessionNow()
	if e, _ := session.Get("epoch").(string); e == "" {
		e = "0"
		if e != sessionEpoch() {
			return dropSession(c, session)
		}
	} else if e != sessionEpoch() {
		return dropSession(c, session)
	}
	if sessionExpired(session.Get("login_at"), session.Get("last_seen"), now, sessionIdle()) {
		secure := isSecureRequest(c)
		session.Clear()
		session.Options(sessions.Options{Path: "/", MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
		_ = session.Save()
		return false
	}
	if last, _ := sessionInt(session.Get("last_seen")); now.Unix()-last >= int64(sessionTouchEvery/time.Second) {
		session.Set("last_seen", now.Unix())
		// параметры куки при сохранении не наследуются от входа: без этого после первого продления пропадал бы флаг Secure
		session.Options(sessions.Options{Path: "/", MaxAge: int(sessionMaxAge / time.Second), HttpOnly: true, Secure: isSecureRequest(c), SameSite: http.SameSiteLaxMode})
		_ = session.Save()
	}
	return true
}

// dropSession стирает сессию, выданную до смены пароля.
func dropSession(c *gin.Context, session sessions.Session) bool {
	session.Clear()
	session.Options(sessions.Options{Path: "/", MaxAge: -1, HttpOnly: true, Secure: isSecureRequest(c), SameSite: http.SameSiteLaxMode})
	_ = session.Save()
	return false
}
