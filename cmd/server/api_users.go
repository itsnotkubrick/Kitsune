package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/events"
	"kitsune/internal/proto"
	"kitsune/internal/sub"
	"kitsune/internal/version"
)

type userView struct {
	db.User
	Active    bool   `json:"active"`
	Protocols int    `json:"protocols"`
	SubURL    string `json:"sub_url"`
}

func subBase(c *gin.Context) string {
	host := requestHost(c.Request)
	if isSecureRequest(c) {
		return "https://" + host
	}
	if cfg := panelCfg.Load(); cfg != nil && cfg.Mode != "" && cfg.Mode != "off" {
		if onAdminLoopback(c.Request) {
			if public := db.GetSetting("public_host", ""); validHostName(public) {
				host = public
			}
		}
		return panelHTTPSBase(cfg, host)
	}
	return "http://" + host
}

func viewUser(c *gin.Context, u db.User, enabledInbounds int) userView {
	return userView{User: u, Active: u.Active(), Protocols: enabledInbounds, SubURL: subBase(c) + "/sub/" + u.SubID}
}

func enabledInbounds() int {
	n := 0
	inbounds, _ := db.GetInbounds()
	for _, ib := range inbounds {
		if ib.Enable {
			n++
		}
	}
	return n
}

func handleGetUsers(c *gin.Context) {
	rememberSubBase(c)
	rememberHost(c)
	users, err := db.GetUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка базы данных"})
		return
	}
	n := enabledInbounds()
	out := []userView{}
	for _, u := range users {
		out = append(out, viewUser(c, u, n))
	}
	c.JSON(http.StatusOK, gin.H{"users": out})
}

type createUserRequest struct {
	Name         string `json:"name"`
	TrafficLimit int64  `json:"traffic_limit"`
	ExpiryDays   int    `json:"expiry_days"`
	ExpiryTime   int64  `json:"expiry_time"`
	IPLimit      int    `json:"ip_limit"`
	Note         string `json:"note"`
	Vision       *bool  `json:"vision"`
	TemplateID   int    `json:"template_id"` // значения шаблона подставляются, явно заданные поля имеют приоритет
	GroupID      int    `json:"group_id"`
}

func handleAddUser(c *gin.Context) {
	rememberHost(c)
	var req createUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}
	if req.TemplateID > 0 {
		t, err := db.GetTemplate(req.TemplateID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if req.TrafficLimit == 0 {
			req.TrafficLimit = t.TrafficLimit
		}
		if req.ExpiryDays == 0 && req.ExpiryTime == 0 {
			req.ExpiryDays = t.Days
		}
		if req.IPLimit == 0 {
			req.IPLimit = t.IPLimit
		}
		if req.Note == "" {
			req.Note = t.Note
		}
		if req.Vision == nil {
			v := t.Vision
			req.Vision = &v
		}
		if req.GroupID == 0 {
			req.GroupID = t.GroupID
		}
	}
	expiry := req.ExpiryTime
	if req.ExpiryDays > 0 {
		expiry = db.NowPlusDays(req.ExpiryDays)
	}
	if req.TrafficLimit < 0 {
		req.TrafficLimit = 0
	}
	if req.IPLimit < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Лимит устройств не может быть отрицательным"})
		return
	}
	u, err := db.CreateUser(req.Name, req.TrafficLimit, expiry, req.IPLimit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать пользователя"})
		return
	}
	patch := db.UserPatch{}
	if req.Note != "" {
		patch.Note = &req.Note
	}
	if req.Vision != nil {
		patch.Vision = req.Vision
	}
	if req.GroupID > 0 {
		patch.GroupID = &req.GroupID
	}
	_ = db.UpdateUser(u.ID, patch)
	markKnownActive(u.ID)
	if err := applyCores(); err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "Пользователь создан, но ядро не приняло конфиг: " + err.Error(), "id": u.ID})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Пользователь создан", "id": u.ID, "name": u.Name})
}

func userID(c *gin.Context) (int, bool) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
		return 0, false
	}
	return id, true
}

func handleUpdateUser(c *gin.Context) {
	id, ok := userID(c)
	if !ok {
		return
	}
	var req struct {
		db.UserPatch
		ExpiryDays *int `json:"expiry_days"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}
	patch := req.UserPatch
	if patch.IPLimit != nil && *patch.IPLimit < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Лимит устройств не может быть отрицательным"})
		return
	}
	if req.ExpiryDays != nil {
		var ms int64
		if *req.ExpiryDays > 0 {
			ms = db.NowPlusDays(*req.ExpiryDays)
		}
		patch.ExpiryTime = &ms
	}
	if err := db.UpdateUser(id, patch); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// изменения уже записаны: если ядро (например, ещё не установленное) не приняло конфиг, это не ошибка сохранения
	if err := applyCores(); err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "Пользователь сохранён, но ядро не приняло конфиг: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Пользователь сохранён"})
}

func handleDeleteUser(c *gin.Context) {
	id, ok := userID(c)
	if !ok {
		return
	}
	if err := db.DeleteUser(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка удаления"})
		return
	}
	_ = applyCores()
	c.JSON(http.StatusOK, gin.H{"message": "Пользователь удалён"})
}

func handleToggleUser(c *gin.Context) {
	id, ok := userID(c)
	if !ok {
		return
	}
	u, err := db.GetUser(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
		return
	}
	en := !u.Enable
	_ = db.UpdateUser(id, db.UserPatch{Enable: &en})
	_ = applyCores()
	c.JSON(http.StatusOK, gin.H{"message": "Статус изменён", "enable": en})
}

func handleResetUserTraffic(c *gin.Context) {
	id, ok := userID(c)
	if !ok {
		return
	}
	if err := db.ResetUserTraffic(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сброса трафика"})
		return
	}
	_ = applyCores() // пользователь мог быть отключён из-за лимита
	c.JSON(http.StatusOK, gin.H{"message": "Трафик сброшен"})
}

// handleRegenSub отзывает старую ссылку подписки пользователя и выдаёт новую.
func handleRegenSub(c *gin.Context) {
	id, ok := userID(c)
	if !ok {
		return
	}
	if _, err := db.RegenSubID(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось выпустить новую ссылку"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Новая ссылка подписки выпущена, старая больше не работает"})
}

type linkView struct {
	InboundID int    `json:"inbound_id"`
	Tag       string `json:"tag"`
	Kind      string `json:"kind"`
	Title     string `json:"title"`
	Core      string `json:"core"`
	URI       string `json:"uri"`
	Config    string `json:"config,omitempty"` // готовый файл настроек (AmneziaWG .conf)
	// Configs – готовые конфиги клиентов для типов без ссылки-подписки (MASQUE): sing-box и Xray, по версиям HTTP.
	Configs []cfgView `json:"configs,omitempty"`
	Note    string    `json:"note,omitempty"`
}

type cfgView struct {
	Label string `json:"label"`
	Text  string `json:"text"`
}

// masqueConfigs – конфиги клиентов MASQUE для пользователя: sing-box 1.15+ (HTTP/3, 2, 1) и Xray 26.10.10+ для v2rayN (HTTP/3, 2).
func masqueConfigs(p *proto.Profile) []cfgView {
	pretty := func(m proto.M) string {
		b, _ := json.MarshalIndent(m, "", "  ")
		return string(b)
	}
	name := map[int]string{3: "HTTP/3 (UDP)", 2: "HTTP/2 (TCP)", 1: "HTTP/1.1 (TCP)"}
	var out []cfgView
	for _, v := range proto.MasqueVersions(false) {
		out = append(out, cfgView{Label: "sing-box 1.15+ · " + name[v], Text: pretty(p.MasqueSingboxConfig(v))})
	}
	for _, v := range proto.MasqueVersions(true) {
		out = append(out, cfgView{Label: "Xray 26.10.10+ / v2rayN · " + name[v], Text: pretty(p.MasqueXrayConfig(v))})
	}
	return out
}

func handleUserLinks(c *gin.Context) {
	id, ok := userID(c)
	if !ok {
		return
	}
	u, err := db.GetUser(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
		return
	}
	rememberSubBase(c)
	env := proto.Env{Host: linkHost(c)}
	inbounds, _ := db.GetInbounds()
	links := []linkView{}
	gm := db.GroupMap()
	for _, ib := range inbounds {
		if !ib.Enable || !db.Allowed(gm, *u, ib.ID) {
			continue
		}
		p, err := proto.NewProfile(ib, *u, env)
		if err != nil {
			continue
		}
		info, _ := proto.Get(proto.Kind(ib.Kind))
		lv := linkView{InboundID: ib.ID, Tag: ib.Tag, Kind: ib.Kind, URI: p.URI(), Config: p.AWGConfig()}
		switch proto.Kind(ib.Kind) {
		case proto.Naive:
			if p.Insecure {
				lv.Note = "Нужен домен и доверенный сертификат: с самоподписанным клиенты не подключатся"
			}
		case proto.AWG, proto.AWG3:
			if p.AWG == nil {
				lv.Note = "Ключи пира появятся после запуска сервера AmneziaWG"
			}
		case proto.Masque:
			lv.Configs = masqueConfigs(p)
			lv.Note = "В подписку не входит: скопируйте конфиг и вставьте его в приложение (sing-box 1.15+ или Xray 26.10.10+, например v2rayN). Трафик MASQUE по людям не считается."
			if p.Insecure {
				lv.Note = "В подписку не входит: скопируйте конфиг и вставьте его в приложение (sing-box 1.15+ или Xray 26.10.10+, например v2rayN). Трафик MASQUE по людям не считается. Сертификат самоподписанный: в конфиге sing-box отключена проверка, в Xray закреплён хеш. С доменом и Let's Encrypt надёжнее."
			}
		}
		if info != nil {
			lv.Title, lv.Core = info.Title, info.Core
		}
		links = append(links, lv)
	}
	c.JSON(http.StatusOK, gin.H{
		"user":        viewUser(c, *u, len(links)),
		"sub_url":     subBase(c) + "/sub/" + u.SubID,
		"connect_url": subBase(c) + "/sub/" + u.SubID + "/connect",
		"progress":    connectProgress(*u),
		"links":       links,
	})
}

// handleSubscription отдаёт подписку: формат выбирается по приложению (User-Agent) или параметру ?format=.
func handleSubscription(c *gin.Context) {
	ip := c.ClientIP()
	if subBlocked(ip) {
		notFound(c) // тот же ответ, что у любого неизвестного адреса: по нему не видно ни обработчика подписок, ни самого лимита
		return
	}
	u, err := db.GetUserBySubID(c.Param("subid"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			subFail(ip)
		}
		notFound(c) // тот же ответ, что у любого неизвестного адреса: по нему не видно, что здесь есть подписки
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("X-Frame-Options", "DENY")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Subscription-Userinfo", sub.UserInfoHeader(*u))
	happ := strings.Contains(strings.ToLower(c.GetHeader("User-Agent")), "happ")
	sub.LoadSubSettings().ApplyHeaders(c.Writer.Header(), happ, sub.LoadClientRouting())
	if sub.WantsPage(c.GetHeader("Accept"), c.GetHeader("User-Agent"), c.Query("format"), c.Query("page")) {
		c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		c.Data(http.StatusOK, "text/html; charset=utf-8", sub.Page(*u, subBase(c)+"/sub/"+u.SubID))
		return
	}
	if !u.Active() {
		c.String(http.StatusForbidden, "Подписка неактивна: срок или лимит трафика исчерпаны")
		return
	}
	if hwid := db.CleanHeader(c.GetHeader("X-HWID"), 128); hwid != "" && c.Request.Method != http.MethodHead {
		ok, _ := db.TouchDevice(u.ID, db.Device{
			HWID: hwid, OS: db.CleanHeader(c.GetHeader("X-Device-OS"), 64),
			OSVersion: db.CleanHeader(c.GetHeader("X-Ver-OS"), 64), Model: db.CleanHeader(c.GetHeader("X-Device-Model"), 128),
		}, u.IPLimit)
		if !ok {
			c.Header("X-Hwid-Limit", "true")
			c.String(http.StatusForbidden, fmt.Sprintf("Достигнут лимит устройств (%d). Обратитесь к администратору: он освободит место, сбросив старые устройства.", u.IPLimit))
			return
		}
		c.Header("X-Hwid-Active", "true")
	}
	profiles := sub.ForClient(sub.Profiles(*u, proto.Env{Host: linkHost(c)}), c.GetHeader("User-Agent"))
	if len(profiles) == 0 {
		c.String(http.StatusNotFound, "В подписке пока нет подключений")
		return
	}
	if c.Request.Method != http.MethodHead {
		_ = db.MarkConnect(u.ID, db.EvSub, appFromUA(c.GetHeader("User-Agent")))
	}
	rt := loadClientRouting()
	switch sub.DetectFormat(c.Query("format"), c.GetHeader("User-Agent")) {
	case sub.FormatClash:
		data, err := sub.Clash(profiles, rt)
		if err == nil {
			c.Header("Content-Type", "application/x-yaml; charset=utf-8")
			c.Header("Content-Disposition", `attachment; filename="kitsune.yaml"`)
			c.Data(http.StatusOK, "application/x-yaml; charset=utf-8", data)
			return
		}
	case sub.FormatXray:
		data, err := sub.XrayJSON(profiles)
		if err == nil {
			c.Data(http.StatusOK, "application/json; charset=utf-8", data)
			return
		}
	case sub.FormatSingbox:
		data, err := sub.Singbox(profiles, rt)
		if err == nil {
			c.Data(http.StatusOK, "application/json; charset=utf-8", data)
			return
		}
	}
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(http.StatusOK, sub.Raw(profiles))
}

func loadClientRouting() sub.Routing { return sub.LoadClientRouting().Compile() }

// ---- Мониторинг трафика и лимитов ----

func StartTrafficMonitor() {
	ticker := time.NewTicker(5 * time.Second)
	lastActive := activeKey()
	notifyDeactivated() // запоминаем исходное состояние, чтобы ловить только новые отключения
	tick := 0
	for range ticker.C {
		tick++
		// Xray: счётчики пользователей раз в 15 секунд (запрос обнуляет их)
		if tick%3 == 0 {
			if stats, err := core.QueryTrafficStats(); err == nil {
				for _, st := range stats {
					// user>>>email>>>traffic>>>uplink|downlink
					parts := strings.Split(st.Name, ">>>")
					if len(parts) >= 4 && parts[0] == "user" && st.Value > 0 {
						_ = db.IncrementClientTraffic(parts[1], st.Value)
					}
				}
			}
		}
		// sing-box (TUIC, Naive): байты из прокси учёта
		for email, n := range core.DrainAcct() {
			_ = db.IncrementClientTraffic(email, n)
		}
		core.EnforceDeviceLimits()
		// Лимит трафика или срок исчерпаны – пользователь выпадает из конфигов ядер.
		notifyDeactivated() // каждый тик: переход «активен → отключён» мог начаться и закончиться между двумя проверками
		if now := activeKey(); now != lastActive {
			lastActive = now
			_ = applyCores()
		}
	}
}

func activeKey() string {
	users, _ := db.GetUsers()
	var sb strings.Builder
	for _, u := range users {
		if u.Active() {
			sb.WriteString(strconv.Itoa(u.ID))
			sb.WriteByte(',')
		}
	}
	return sb.String() + "|" + version.Version
}

// handleAWGConfig отдаёт файл .conf AmneziaWG для пользователя.
func handleAWGConfig(c *gin.Context) {
	id, ok := userID(c)
	if !ok {
		return
	}
	ibID, _ := strconv.Atoi(c.Param("inbound"))
	u, err := db.GetUser(id)
	ib, err2 := db.GetInboundByID(ibID)
	if err != nil || err2 != nil || (ib.Kind != string(proto.AWG) && ib.Kind != string(proto.AWG3)) {
		c.String(http.StatusNotFound, "Не найдено")
		return
	}
	p, err := proto.NewProfile(*ib, *u, proto.Env{Host: linkHost(c)})
	if err != nil || p.AWG == nil {
		c.String(http.StatusNotFound, "Ключи пира ещё не созданы")
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.conf"`, db.CleanName(ib.Tag), db.CleanName(u.Name)))
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(p.AWGConfig()))
}

var (
	knownMu     sync.Mutex
	knownActive = map[int]bool{}
)

// markKnownActive запоминает нового пользователя как активного: так отключение лимитом сразу после создания не пропадёт.
func markKnownActive(id int) {
	knownMu.Lock()
	knownActive[id] = true
	knownMu.Unlock()
}

// notifyDeactivated сообщает об отключённых лимитом или сроком пользователях.
func notifyDeactivated() {
	knownMu.Lock()
	defer knownMu.Unlock()
	users, _ := db.GetUsers()
	for _, u := range users {
		was, seen := knownActive[u.ID]
		now := u.Active()
		knownActive[u.ID] = now
		if seen && was && !now && u.Enable {
			reason := "лимит трафика исчерпан"
			if u.ExpiryTime > 0 && u.ExpiryTime < time.Now().UnixMilli() {
				reason = "срок истёк"
			}
			events.Notify("user_limit", strconv.Itoa(u.ID), "пользователь "+u.Name+" отключён: "+reason, time.Hour)
		}
	}
}

func handleUserDevices(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	list, err := db.ListDevices(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"devices": list})
}

func handleDeleteUserDevice(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	did, err := strconv.ParseInt(c.Param("did"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный номер устройства"})
		return
	}
	if err := db.DeleteDevice(id, did); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// bulkMaxUsers – сколько пользователей можно затронуть одним запросом.
const bulkMaxUsers = 500

// bulkApply пересобирает ядра после группового действия (в тестах подменяется).
var bulkApply = applyCores

// handleBulkUsers применяет одно действие сразу к нескольким пользователям и пересобирает ядра один раз:
// по запросу на каждого панель перезапускала бы ядра столько раз, сколько выбрано человек.
func handleBulkUsers(c *gin.Context) {
	var req struct {
		IDs    []int  `json:"ids"`
		Action string `json:"action"`
		Days   int    `json:"days"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}
	switch req.Action {
	case "enable", "disable", "reset_traffic", "delete":
	case "extend":
		if req.Days < 1 || req.Days > 3650 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Срок продления: от 1 до 3650 дней"})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неизвестное действие"})
		return
	}
	seen := map[int]bool{}
	ids := make([]int, 0, len(req.IDs))
	for _, id := range req.IDs {
		if id > 0 && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Не выбрано ни одного пользователя"})
		return
	}
	if len(ids) > bulkMaxUsers {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("За один раз можно выбрать не больше %d пользователей", bulkMaxUsers)})
		return
	}

	done, skipped, failed := 0, 0, 0
	now := time.Now().UnixMilli()
	for _, id := range ids {
		u, err := db.GetUser(id)
		if err != nil {
			failed++
			continue
		}
		var opErr error
		switch req.Action {
		case "enable", "disable":
			en := req.Action == "enable"
			if u.Enable == en {
				skipped++
				continue
			}
			opErr = db.UpdateUser(id, db.UserPatch{Enable: &en})
		case "reset_traffic":
			opErr = db.ResetUserTraffic(id)
		case "delete":
			opErr = db.DeleteUser(id)
		case "extend":
			if u.ExpiryTime == 0 { // бессрочному продлевать нечего
				skipped++
				continue
			}
			base := u.ExpiryTime
			if base < now {
				base = now
			}
			ms := base + int64(req.Days)*24*60*60*1000
			opErr = db.UpdateUser(id, db.UserPatch{ExpiryTime: &ms})
		}
		if opErr != nil {
			failed++
			continue
		}
		done++
	}
	if done > 0 {
		if err := bulkApply(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "done": done, "skipped": skipped, "failed": failed})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": bulkMessage(req.Action, req.Days, done, skipped, failed), "done": done, "skipped": skipped, "failed": failed})
}

func bulkMessage(action string, days, done, skipped, failed int) string {
	verb := map[string]string{"enable": "включено", "disable": "отключено", "reset_traffic": "трафик сброшен", "delete": "удалено", "extend": fmt.Sprintf("продлено на %d дн.", days)}[action]
	msg := fmt.Sprintf("Готово: %s – %d", verb, done)
	if skipped > 0 {
		if action == "extend" {
			msg += fmt.Sprintf(". Пропущено бессрочных: %d", skipped)
		} else {
			msg += fmt.Sprintf(". Уже в нужном состоянии: %d", skipped)
		}
	}
	if failed > 0 {
		msg += fmt.Sprintf(". Не удалось: %d", failed)
	}
	return msg
}
