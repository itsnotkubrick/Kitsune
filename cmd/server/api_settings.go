package main

import (
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/sub"
)

func handleClientRoutingGet(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"routing": sub.LoadClientRouting(), "services": sub.Services, "configured": db.GetSetting("client_routing", "") != ""})
}

func handleClientRoutingSet(c *gin.Context) {
	cr := sub.LoadClientRouting()
	if err := c.ShouldBindJSON(&cr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}
	switch cr.Mode {
	case "ru-direct":
		cr.Mode = "local-direct"
	case "all", "services", "local-direct", "custom":
	default:
		cr.Mode = "all"
	}
	if cr.LocalDNS != "" && net.ParseIP(cr.LocalDNS) == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "DNS для прямых доменов: нужен IP-адрес, например 77.88.8.8"})
		return
	}
	if err := sub.SaveClientRouting(cr); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// Happ применяет профиль маршрутизации заново, когда растёт LastUpdated.
	ss := sub.LoadSubSettings()
	ss.RoutingUpdated = time.Now().Unix()
	_ = sub.SaveSubSettings(ss)
	c.JSON(http.StatusOK, gin.H{"message": "Маршрутизация клиентов сохранена. Приложения получат её при следующем обновлении подписки."})
}

func handlePortModeGet(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"mode": db.GetSetting("port_mode", "separate"), "router_running": core.RouterRunning()})
}

// handlePortModeSet переключает «каждый протокол на своём порту» и «всё на 443 по SNI».
func handlePortModeSet(c *gin.Context) {
	var req struct {
		Mode string `json:"mode"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || (req.Mode != "separate" && req.Mode != "single443") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Режим: separate или single443"})
		return
	}
	old := db.GetSetting("port_mode", "separate")
	_ = db.SetSetting("port_mode", req.Mode)
	if err := applyCores(); err != nil {
		_ = db.SetSetting("port_mode", old)
		_ = applyCores()
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Режим применён. Клиентам нужно обновить подписку: адреса и порты в ссылках изменились."})
}

func handleSubSettingsGet(c *gin.Context) {
	c.JSON(http.StatusOK, sub.LoadSubSettings())
}

func handleSubSettingsSet(c *gin.Context) {
	s := sub.LoadSubSettings()
	if err := c.ShouldBindJSON(&s); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}
	if msg := s.Validate(); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}
	s.RoutingUpdated = sub.LoadSubSettings().RoutingUpdated // отметку времени меняет только смена маршрутизации
	if err := sub.SaveSubSettings(s); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Оформление подписки сохранено. Приложения подхватят его при следующем обновлении подписки."})
}
