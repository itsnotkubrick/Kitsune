package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"kitsune/internal/check"
	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/metrics"
	"kitsune/internal/proto"
	"kitsune/internal/version"
)

func handleSystemStatus(c *gin.Context) {
	bin := core.XrayBinary()
	state := "not-installed"
	ver := "не установлена"
	if bin != "" {
		state = "stopped"
		if core.XrayProc.Running() {
			state = "active"
		}
		if out, err := exec.Command(bin, "version").Output(); err == nil {
			if f := strings.Fields(strings.SplitN(string(out), "\n", 2)[0]); len(f) >= 2 {
				ver = f[1]
			}
		}
	}
	ram := "—"
	if st := core.XrayProc.Status(); st.PID > 0 {
		if out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(st.PID)).Output(); err == nil {
			if kb, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64); err == nil && kb > 0 {
				ram = strconv.FormatFloat(float64(kb)/1024.0, 'f', 1, 64) + " MB"
			}
		}
	}
	inbounds, _ := db.GetInbounds()
	users, _ := db.GetUsers()
	active := 0
	for _, u := range users {
		if u.Active() {
			active++
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"xray_state":      state,
		"xray_version":    ver,
		"kitsune_version": "v" + version.Version,
		"ram_usage":       ram,
		"total_inbounds":  len(inbounds),
		"active_clients":  active,
		"server_time":     time.Now().Format("15:04:05"),
	})
}

func handleRestartXray(c *gin.Context) {
	if err := applyCores(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Ядро перезапущено"})
}

// handleInstallXray ставит последнюю версию Xray (с проверкой SHA-256) и запускает ядро.
func handleInstallXray(c *gin.Context) {
	if err := core.InstallXray(); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if err := applyCores(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Xray установлен, но не запустился: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Xray " + core.InstalledVersion("xray") + " установлен и запущен"})
}

func handleCores(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"cores": core.Components(), "status": core.Statuses()})
}

// handleCoresLatest сравнивает установленные версии ядер с последними выпусками на GitHub.
func handleCoresLatest(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"latest": core.LatestVersions(c.Request.Context())})
}

// handleCoreSettingsGet отдаёт настройки ядер (кроме Xray) и значения по умолчанию.
func handleCoreSettingsGet(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"settings": core.LoadCoreSettings(), "defaults": core.DefaultCoreSettings()})
}

// handleCoreSettingsSet меняет настройки одного ядра (singbox, mtg, mita, telemt, awg), проверяет их и перезапускает ядра.
func handleCoreSettingsSet(c *gin.Context) {
	id := c.Param("id")
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 64<<10))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}
	cur := core.LoadCoreSettings()
	next := cur
	var dst interface{}
	switch id {
	case "singbox":
		dst = &next.Singbox
	case "mtg":
		dst = &next.MTG
	case "mita":
		dst = &next.Mita
	case "telemt":
		dst = &next.Telemt
	case "awg":
		dst = &next.AWG
	default:
		c.JSON(http.StatusNotFound, gin.H{"error": "У этого ядра нет настроек"})
		return
	}
	if err := json.Unmarshal(body, dst); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}
	if err := next.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := core.SaveCoreSettings(next); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := applyCores(); err != nil {
		_ = core.SaveCoreSettings(cur) // ядро не приняло: возвращаем прежние настройки
		_ = applyCores()
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ядро не приняло настройки, оставлены прежние: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Настройки сохранены, ядро перезапущено"})
}

func handleInstallCore(c *gin.Context) {
	id := c.Param("id")
	install := core.InstallComponent
	if c.Query("fresh") == "1" { // свежий выпуск (младше 3 суток) по явному решению человека в интерфейсе
		install = core.InstallComponentFresh
	}
	rollback := c.Query("pinned") == "1" // откат к проверенной версии по решению человека
	if rollback {
		if id != "xray" { // откат до проверенной версии есть только у Xray: у остальных ядер выпуски не ломали совместимость с клиентами
			c.JSON(http.StatusBadRequest, gin.H{"error": "Откат до проверенной версии доступен только для Xray"})
			return
		}
		install = core.InstallComponentPinned
	}
	if err := install(id); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if err := applyCores(); err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "Установлено, но применить конфиг не удалось: " + err.Error()})
		return
	}
	if rollback {
		c.JSON(http.StatusOK, gin.H{"message": "Ядро возвращено к проверенной версии " + core.InstalledVersion(id)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Ядро установлено, версия " + core.InstalledVersion(id)})
}

func handleCheck(c *gin.Context) {
	rep := check.Run()
	if c.Query("deep") == "1" {
		d := check.Deep()
		rep.Items = append(rep.Items, d.Items...)
		rep.Bad += d.Bad
		rep.Warn += d.Warn
	}
	c.JSON(http.StatusOK, rep)
}

type fixRequest struct {
	DryRun bool     `json:"dry_run"`
	Codes  []string `json:"codes"` // какие исправления выполнить (пусто – все доступные)
}

// handleFix – безопасные автоисправления, затем повторная проверка.
func handleFix(c *gin.Context) {
	var req fixRequest
	_ = c.ShouldBindJSON(&req)
	plan := check.Run().Plan()
	if len(req.Codes) > 0 { // только выбранные, и только из доступных
		allowed := map[string]bool{}
		for _, c := range req.Codes {
			allowed[c] = true
		}
		var picked []string
		for _, c := range plan {
			if allowed[c] {
				picked = append(picked, c)
			}
		}
		plan = picked
	}
	if req.DryRun {
		c.JSON(http.StatusOK, gin.H{"plan": plan})
		return
	}
	var done, failed []string
	for _, code := range plan {
		msg, err := check.Apply(code, applyCores)
		if err != nil {
			failed = append(failed, err.Error())
			continue
		}
		done = append(done, afterFix(c, code, msg))
	}
	c.JSON(http.StatusOK, gin.H{"plan": plan, "done": done, "failed": failed, "report": check.Run()})
}

func portListening(port int) bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 400*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func handleMetrics(c *gin.Context) {
	snap, hist := metrics.Get()
	inbounds, _ := db.GetInbounds()
	users, _ := db.GetUsers()

	type inboundStat struct {
		ID        int    `json:"id"`
		Tag       string `json:"tag"`
		Protocol  string `json:"protocol"`
		Kind      string `json:"kind"`
		Port      int    `json:"port"`
		Enable    bool   `json:"enable"`
		Clients   int    `json:"clients"`
		Used      int64  `json:"used"`
		Listening bool   `json:"listening"`
	}
	ibs := []inboundStat{}
	for _, ib := range inbounds {
		info, _ := proto.Get(proto.Kind(ib.Kind))
		listening := false
		if info != nil && info.Net == "udp" {
			listening = core.XrayProc.Running() && ib.Enable
		} else {
			listening = portListening(ib.Port)
		}
		var used int64
		_ = db.DB.QueryRow("SELECT COALESCE(SUM(used_traffic), 0) FROM clients WHERE inbound_id = ?", ib.ID).Scan(&used)
		ibs = append(ibs, inboundStat{ID: ib.ID, Tag: ib.Tag, Protocol: ib.Protocol, Kind: ib.Kind, Port: ib.Port, Enable: ib.Enable,
			Clients: len(users), Used: used, Listening: listening})
	}

	type top struct {
		Email string `json:"email"`
		Used  int64  `json:"used"`
		Limit int64  `json:"limit"`
	}
	tops := []top{}
	var totalUsed int64
	active, disabled, expired, expiring := 0, 0, 0, 0
	nowMs := time.Now().UnixMilli()
	for _, u := range users {
		totalUsed += u.UsedTraffic
		tops = append(tops, top{Email: u.Name, Used: u.UsedTraffic, Limit: u.TrafficLimit})
		switch {
		case !u.Enable:
			disabled++
		case !u.Active():
			expired++
		default:
			active++
			if u.ExpiryTime > nowMs && u.ExpiryTime < nowMs+7*24*3600*1000 {
				expiring++
			}
		}
	}
	usersTotal := len(tops)
	sort.Slice(tops, func(i, j int) bool { return tops[i].Used > tops[j].Used })
	if len(tops) > 30 {
		tops = tops[:30]
	}

	cfgState := "missing"
	var cfgMod int64
	if st, err := os.Stat(core.ConfigPath); err == nil {
		cfgState, cfgMod = "ok", st.ModTime().Unix()
		if data, err := os.ReadFile(core.ConfigPath); err != nil || !json.Valid(data) {
			cfgState = "invalid"
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"host":     snap,
		"history":  hist,
		"inbounds": ibs,
		"clients":  gin.H{"active": active, "disabled": disabled, "expired": expired, "expiring": expiring, "total": usersTotal},
		"traffic":  gin.H{"total_used": totalUsed, "top": tops},
		"config":   gin.H{"state": cfgState, "modified": cfgMod},
		"cores":    core.Statuses(),
		"version":  version.Version,
	})
}

// ---- Настройки сервера ----

func handleServerSettingsGet(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"public_host": db.GetSetting("public_host", ""),
		"effective":   linkHost(c),
	})
}

func handleServerSettingsSet(c *gin.Context) {
	var req struct {
		PublicHost string `json:"public_host"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}
	h := strings.TrimSpace(req.PublicHost)
	if strings.ContainsAny(h, " /\\?#@") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Адрес должен быть IP или доменом без схемы и пути"})
		return
	}
	_ = db.SetSetting("public_host", h)
	if err := applyCores(); err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "Адрес сервера сохранён, но ядро не приняло конфиг: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Адрес сервера сохранён, конфиги пересобраны"})
}

// ---- Глобальные настройки Xray ----

func handleXraySettingsGet(c *gin.Context) {
	c.JSON(http.StatusOK, core.LoadXraySettings())
}

func handleXraySettingsSet(c *gin.Context) {
	s := core.LoadXraySettings()
	if err := c.ShouldBindJSON(&s); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных: " + err.Error()})
		return
	}
	old := core.LoadXraySettings()
	if err := core.SaveXraySettings(s); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := applyCores(); err != nil {
		// Откат: прежние настройки и рабочий конфиг остаются.
		_ = core.SaveXraySettings(old)
		_ = applyCores()
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Настройки Xray применены"})
}

// handleXrayConfigPreview отдаёт собранный config.json без секретов-ключей REALITY.
func handleXrayConfigPreview(c *gin.Context) {
	cfg, err := core.BuildXrayConfig(core.PublicEnv())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, maskSecretKeys(cfg))
}

// maskSecretKeys заменяет закрытые ключи в собранном конфиге заглушкой. Предпросмотр только для чтения,
// обратно конфиг из панели не пишется (он каждый раз собирается из базы).
func maskSecretKeys(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return gin.H{}
	}
	var out any
	if json.Unmarshal(b, &out) != nil {
		return gin.H{}
	}
	var walk func(x any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				if k == "privateKey" || k == "secretKey" || k == "private_key" {
					t[k] = "••••"
					continue
				}
				walk(val)
			}
		case []any:
			for _, val := range t {
				walk(val)
			}
		}
	}
	walk(out)
	return out
}
