package main

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
	"kitsune/internal/events"
	"kitsune/internal/totp"
)

func handleTOTPStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"enabled": db.GetSetting("totp_enabled", "") == "1"})
}

// handleTOTPSetup создаёт новый секрет (пока не включён) и отдаёт ссылку для QR-кода.
func handleTOTPSetup(c *gin.Context) {
	if db.GetSetting("totp_enabled", "") == "1" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Двухфакторный вход уже включён"})
		return
	}
	secret, err := totp.NewSecret()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать секрет"})
		return
	}
	_ = db.SetSetting("totp_pending", secret)
	c.JSON(http.StatusOK, gin.H{"secret": secret, "uri": totp.URI(secret, db.GetSetting("admin_username", "admin"), "Kitsune")})
}

// handleTOTPEnable включает вход по коду после проверки первого кода от приложения.
func handleTOTPEnable(c *gin.Context) {
	var req struct {
		Code string `json:"code"`
	}
	_ = c.ShouldBindJSON(&req)
	secret := db.GetSetting("totp_pending", "")
	if secret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Сначала создайте секрет"})
		return
	}
	step, ok := totp.Verify(secret, req.Code, time.Now())
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Код не подошёл: проверьте время на телефоне и попробуйте ещё раз"})
		return
	}
	_ = db.SetSetting("totp_secret", secret)
	_ = db.SetSetting("totp_last_step", strconv.FormatUint(step, 10))
	_ = db.SetSetting("totp_enabled", "1")
	_ = db.SetSetting("totp_pending", "")
	c.JSON(http.StatusOK, gin.H{"message": "Двухфакторный вход включён"})
}

// handleTOTPDisable выключает вход по коду; нужны пароль и действующий код.
func handleTOTPDisable(c *gin.Context) {
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	_ = c.ShouldBindJSON(&req)
	if db.GetSetting("totp_enabled", "") != "1" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Двухфакторный вход не включён"})
		return
	}
	ip := c.ClientIP()
	slot, verdict := loginEnter(ip) // см. handleLogin
	if verdict != loginAllowed {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Слишком много неудачных попыток. Подождите 10 минут."})
		return
	}
	defer slot.done()
	if !db.CheckAdminAuth(db.GetSetting("admin_username", "admin"), req.Password) {
		slot.fail()
		c.JSON(http.StatusForbidden, gin.H{"error": "Неверный пароль"})
		return
	}
	ok, limited := totpCheck(req.Code)
	if limited {
		totpLimitedNotice(db.GetSetting("admin_username", "admin"), ip)
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Слишком много неверных кодов. Подождите 10 минут."})
		return
	}
	if !ok { // неверный или уже использованный код, как при входе
		slot.fail()
		events.Audit(db.GetSetting("admin_username", "admin"), "Неверный код при отключении двухфакторного входа", ip)
		c.JSON(http.StatusForbidden, gin.H{"error": "Неверный или уже использованный код"})
		return
	}
	slot.success()
	for _, k := range []string{"totp_enabled", "totp_secret", "totp_pending", "totp_last_step"} {
		_ = db.SetSetting(k, "")
	}
	c.JSON(http.StatusOK, gin.H{"message": "Двухфакторный вход выключен"})
}
