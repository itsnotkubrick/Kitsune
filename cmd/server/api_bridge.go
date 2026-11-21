package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"kitsune/internal/bridge"
	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/proto"
)

var bridgeConfigMu sync.Mutex
var bridgeApplyCores = applyCores
var bridgeProbeSlots = make(chan struct{}, 2)

// handleBridgesGet: узлы-мосты и порты, которые на них нужно переслать.
func handleBridgesGet(c *gin.Context) {
	inbounds, err := db.GetInbounds()
	if err != nil {
		c.JSON(500, gin.H{"error": "Не удалось прочитать подключения"})
		return
	}
	env := core.PublicEnv()
	type prof struct {
		Tag     string `json:"tag"`
		Title   string `json:"title"`
		Net     string `json:"net"`
		Port    int    `json:"port"`
		Relayed bool   `json:"relayed"`
	}
	var profiles []prof
	for _, ib := range inbounds {
		if !ib.Enable {
			continue
		}
		info, ok := proto.Get(proto.Kind(ib.Kind))
		if !ok {
			continue
		}
		port := ib.Port
		if proto.Routed(ib, env) {
			port = 443
		}
		profiles = append(profiles, prof{Tag: ib.Tag, Title: info.Title, Net: info.Net, Port: port, Relayed: bridge.Relayable(proto.Kind(ib.Kind))})
	}
	c.JSON(http.StatusOK, gin.H{
		"nodes":    bridge.List(),
		"forwards": bridge.Forwards(inbounds, env),
		"profiles": profiles,
		"status":   bridgeStatuses(),
		"exit":     serverIPv4(c),
	})
}

// handleBridgesSet сохраняет узлы. Подписки пересобираются сами при следующем обновлении у клиентов.
func handleBridgesSet(c *gin.Context) {
	bridgeConfigMu.Lock()
	defer bridgeConfigMu.Unlock()
	var req struct {
		Nodes []bridge.Node `json:"nodes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}
	nodes, err := bridge.Validate(req.Nodes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Имя для REALITY должно обслуживаться тем же сайтом-маскировкой: иначе на чужой запрос сервер выдаст себя
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	if err := checkNodeSNIs(ctx, nodes); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	inbounds, err := db.GetInbounds()
	if err != nil {
		c.JSON(500, gin.H{"error": "Не удалось прочитать подключения"})
		return
	}
	for _, n := range nodes {
		if n.Enabled {
			if err := bridge.ValidatePorts(n.Select(inbounds), core.PublicEnv()); err != nil {
				c.JSON(400, gin.H{"error": err.Error()})
				return
			}
		}
	}
	previous := bridge.List()
	before := bridgeBindings(previous, inbounds)
	unfreeze := bridge.FreezeSubscriptions(previous)
	defer unfreeze()
	nodes, err = bridge.Save(nodes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	msg := "Узлы сохранены. Клиенты получат дополнительные подключения при следующем обновлении подписки."
	if !sameStrings(before, bridgeBindings(nodes, inbounds)) { // список принимаемых REALITY имён изменился: ядру нужен новый конфиг
		if err := bridgeApplyCores(); err != nil {
			_, rollbackErr := bridge.Save(previous)
			if rollbackErr == nil {
				rollbackErr = bridgeApplyCores()
			}
			message := "Не удалось применить имена сайтов; прежние узлы восстановлены"
			if rollbackErr != nil {
				message = "Ошибка применения и отката; проверьте состояние ядер"
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": message})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"nodes": nodes, "message": msg})
}

// handleBridgeScript отдаёт скрипт для узла: пересылка портов выбранных подключений (пусто – всех) на основной сервер.
func handleBridgeScript(c *gin.Context) {
	var req struct {
		Only          []string `json:"only"`
		SelectionMode string   `json:"selection_mode"`
	}
	if c.ShouldBindJSON(&req) != nil {
		c.JSON(400, gin.H{"error": "Неверный формат данных"})
		return
	}
	inbounds, err := db.GetInbounds()
	if err != nil {
		c.JSON(500, gin.H{"error": "Не удалось прочитать подключения"})
		return
	}
	if req.SelectionMode != "" && req.SelectionMode != "all" && req.SelectionMode != "selected" && req.SelectionMode != "none" {
		c.JSON(400, gin.H{"error": "Неверный режим выбора"})
		return
	}
	if req.SelectionMode == "selected" && len(req.Only) == 0 {
		c.JSON(400, gin.H{"error": "Выберите подключение"})
		return
	}
	selected := (bridge.Node{Only: req.Only, SelectionMode: req.SelectionMode}).Select(inbounds)
	if err := bridge.ValidatePorts(selected, core.PublicEnv()); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	exit := serverIPv4(c)
	script, err := bridge.Script(exit, bridge.Forwards(selected, core.PublicEnv()))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"script": script, "exit": exit})
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

// checkNodeSNIs проверяет, что сайт-маскировка каждого REALITY-подключения отвечает настоящим сертификатом на имя узла.
func checkNodeSNIs(ctx context.Context, nodes []bridge.Node) error {
	var names []string
	for _, n := range nodes {
		if n.Enabled && n.SNI != "" {
			names = append(names, n.SNI)
		}
	}
	if len(names) == 0 {
		return nil
	}
	inbounds, err := db.GetInbounds()
	if err != nil {
		return fmt.Errorf("не удалось прочитать подключения")
	}
	for _, ib := range inbounds {
		if !ib.Enable || (ib.Kind != string(proto.VlessReality) && ib.Kind != string(proto.VlessXHTTP)) {
			continue
		}
		s := proto.ParseSettings(ib.Settings)
		target := s.Target
		if target == "" {
			target = s.SNI + ":443"
		}
		for _, n := range nodes {
			if !n.Enabled || n.SNI == "" || !n.Takes(ib.Tag) {
				continue
			}
			name := n.SNI
			if err := realityTargetServes(ctx, target, name); err != nil {
				return fmt.Errorf("сайт-маскировка %s не обслуживает имя %s (%v). Возьмите имя, которое отдаёт тот же сайт, например соседний поддомен", target, name, err)
			}
		}
	}
	return nil
}

// realityTargetServes делает рукопожатие TLS с сайтом-маскировкой под именем name и проверяет сертификат.
func realityTargetServes(ctx context.Context, target, name string) error {
	d := &net.Dialer{Timeout: 6 * time.Second}
	dialer := tls.Dialer{NetDialer: d, Config: &tls.Config{ServerName: name, MinVersion: tls.VersionTLS13}}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	return conn.Close()
}

// handleBridgeCheck: отвечают ли TCP-порты узла. Проверка идёт с сервера, а не из сети клиента: она показывает, что пересылка
// на узле настроена и порт открыт, но не заменяет замер из мобильной сети.
func handleBridgeCheck(c *gin.Context) {
	select {
	case bridgeProbeSlots <- struct{}{}:
		defer func() { <-bridgeProbeSlots }()
	default:
		c.JSON(429, gin.H{"error": "Проверка уже выполняется"})
		return
	}
	var req struct {
		Host          string   `json:"host"`
		Only          []string `json:"only"`
		SelectionMode string   `json:"selection_mode"`
	}
	if c.ShouldBindJSON(&req) != nil {
		c.JSON(400, gin.H{"error": "Неверный формат данных"})
		return
	}
	if req.SelectionMode != "" && req.SelectionMode != "all" && req.SelectionMode != "selected" && req.SelectionMode != "none" {
		c.JSON(400, gin.H{"error": "Неверный режим выбора"})
		return
	}
	if req.SelectionMode == "selected" && len(req.Only) == 0 {
		c.JSON(400, gin.H{"error": "Выберите подключение"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	addr, err := bridge.ResolveHostContext(ctx, strings.ToLower(strings.TrimSpace(req.Host)))
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	inbounds, err := db.GetInbounds()
	if err != nil {
		c.JSON(500, gin.H{"error": "Не удалось прочитать подключения"})
		return
	}
	selected := (bridge.Node{Only: req.Only, SelectionMode: req.SelectionMode}).Select(inbounds)
	if err := bridge.ValidatePorts(selected, core.PublicEnv()); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	out := bridge.ProbePorts(ctx, addr, bridge.Forwards(selected, core.PublicEnv()))
	c.JSON(200, gin.H{"results": out, "probe_kind": "tcp_connect", "protocol_verified": false})
}

func bridgeBindings(nodes []bridge.Node, inbounds []db.Inbound) []string {
	var out []string
	for _, n := range nodes {
		if !n.Enabled || n.SNI == "" {
			continue
		}
		for _, ib := range inbounds {
			if ib.Enable && (ib.Kind == string(proto.VlessReality) || ib.Kind == string(proto.VlessXHTTP)) && n.Takes(ib.Tag) {
				out = append(out, ib.Tag+"/"+n.SNI)
			}
		}
	}
	return out
}

func registerBridgeRoutes(api *gin.RouterGroup) {
	api.GET("/bridges", handleBridgesGet)
	api.PUT("/bridges", handleBridgesSet)
	api.POST("/bridges/script", handleBridgeScript)
	api.POST("/bridges/check", handleBridgeCheck)
}
