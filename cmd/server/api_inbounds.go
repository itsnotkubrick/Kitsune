package main

import (
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"

	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/proto"
)

func handleProtocols(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"protocols": proto.Catalog})
}

// protocolName – имя xray-протокола для старого поля inbounds.protocol.
func protocolName(k proto.Kind) string {
	switch k {
	case proto.VlessReality, proto.VlessXHTTP, proto.VlessWS:
		return "vless"
	case proto.TrojanGRPC:
		return "trojan"
	case proto.VmessWS:
		return "vmess"
	case proto.SS2022:
		return "shadowsocks"
	case proto.Hysteria2:
		return "hysteria"
	}
	return string(k)
}

type inboundView struct {
	db.Inbound
	// Перекрывает db.Inbound.PrivateKey: на внешнем уровне поле всегда пустое и опускается.
	PrivateKey    string         `json:"private_key,omitempty"`
	HasPrivateKey bool           `json:"has_private_key"`
	Settings      map[string]any `json:"settings"`
	Title         string         `json:"title"`
	Core          string         `json:"core"`
	Net           string         `json:"net"`
	Clients       int            `json:"clients"`
	Listening     bool           `json:"listening"`
	NeedsDomain   bool           `json:"needs_domain"`
}

func viewInbound(ib db.Inbound, users int) inboundView {
	var st map[string]any
	_ = json.Unmarshal([]byte(ib.Settings), &st)
	if st == nil {
		st = map[string]any{}
	}
	// Закрытые ключи наружу не отдаём
	delete(st, "private_key")
	v := inboundView{Inbound: ib, Settings: st, Clients: users, HasPrivateKey: ib.PrivateKey != ""}
	if info, ok := proto.Get(proto.Kind(ib.Kind)); ok {
		v.Title, v.Core, v.Net = info.Title, info.Core, info.Net
		var ps proto.Settings
		if json.Unmarshal([]byte(ib.Settings), &ps) == nil {
			v.NeedsDomain = proto.NeedsDomain(proto.Kind(ib.Kind), ps)
		}
	}
	v.Inbound.Settings = ""
	return v
}

func handleGetInbounds(c *gin.Context) {
	rememberHost(c)
	inbounds, err := db.GetInbounds()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка базы данных"})
		return
	}
	users, _ := db.GetUsers()
	out := []inboundView{}
	for _, ib := range inbounds {
		v := viewInbound(ib, len(users))
		v.Listening = portListening(ib.Port)
		out = append(out, v)
	}
	c.JSON(http.StatusOK, gin.H{"inbounds": out})
}

type inboundRequest struct {
	Kind     string         `json:"kind"`
	Tag      string         `json:"tag"`
	Port     int            `json:"port"`
	Enable   *bool          `json:"enable"`
	Settings map[string]any `json:"settings"`
}

// buildSettings накладывает значения формы на настройки и добирает умолчания и ключи.
func buildSettings(kind proto.Kind, base proto.Settings, patch map[string]any) (proto.Settings, error) {
	if raw, has := patch["header_key"]; has && kind == proto.AWG3 {
		patch = maps.Clone(patch)
		switch v := raw.(type) {
		case nil:
			delete(patch, "header_key") // не задан: сохранённый ключ остаётся
		case string:
			if strings.TrimSpace(v) == "" {
				delete(patch, "header_key")
			} else {
				hk, err := proto.NormalizeHeaderKey(v)
				if err != nil {
					return base, err
				}
				patch["header_key"] = hk
			}
		default:
			return base, fmt.Errorf("ключ защиты заголовков должен быть строкой: 64 символа hex или 44 символа base64")
		}
	}
	if len(patch) > 0 {
		merged := map[string]any{}
		raw, _ := json.Marshal(base)
		_ = json.Unmarshal(raw, &merged)
		for k, v := range patch {
			if v == nil || v == "" {
				delete(merged, k) // пустое значение = вернуть умолчание
				continue
			}
			merged[k] = v
		}
		raw, _ = json.Marshal(merged)
		var s proto.Settings
		if err := json.Unmarshal(raw, &s); err != nil {
			return base, err
		}
		base = s
	}
	if err := base.Fill(kind); err != nil {
		return base, err
	}
	if kind == proto.AWG3 {
		// итоговое значение после слияния: ключ всегда hex на 32 байта
		hk, err := proto.NormalizeHeaderKey(base.HeaderKey)
		if err != nil {
			return base, err
		}
		base.HeaderKey = hk
	}
	return base, nil
}

func validateInbound(kind proto.Kind, s proto.Settings, port int, exceptID int) error {
	info, ok := proto.Get(kind)
	if !ok {
		return fmt.Errorf("неизвестный тип подключения %q", kind)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("порт должен быть от 1 до 65535")
	}
	if portTaken(port, info.Net, exceptID) {
		return fmt.Errorf("порт %d уже занят другим подключением", port)
	}
	if s.CertMode == "custom" {
		if s.CertFile == "" || s.KeyFile == "" {
			return fmt.Errorf("для своего сертификата укажите файлы сертификата и ключа")
		}
		if err := validateCustomCert(s.CertFile, s.KeyFile); err != nil {
			return err
		}
	}
	if kind == proto.AWG3 && s.HeaderKey != "" {
		for name, v := range map[string]string{"S1": s.S1, "S2": s.S2, "S3": s.S3, "S4": s.S4} {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err != nil || n < 12 {
				return fmt.Errorf("с защитой заголовков %s должен быть не меньше 12", name)
			}
		}
	}
	if kind == proto.AWG || kind == proto.AWG3 {
		for name, v := range map[string]string{"PersistentKeepalive": s.Keepalive, "RekeyAfterTime": s.RekeyAfterTime,
			"RekeyTimeout": s.RekeyTimeout, "RejectAfterTime": s.RejectAfterTime, "KeepaliveTimeout": s.KeepaliveTimeout,
			"MaxHandshakeAttempts": s.MaxHandshakeAttempts, "ContentPaddingAddition": s.ContentPaddingAddition} {
			if strings.TrimSpace(v) != "" && !proto.IsRange(v) {
				return fmt.Errorf("%s: число или диапазон вида 25-35", name)
			}
		}
		if _, _, err := net.ParseCIDR(s.Subnet); err != nil {
			return fmt.Errorf("подсеть туннеля задана неверно (пример: 10.8.1.0/24)")
		}
	}
	if strings.TrimSpace(s.XrayPatch) != "" {
		var tmp map[string]any
		if err := json.Unmarshal([]byte(s.XrayPatch), &tmp); err != nil {
			return fmt.Errorf("свой JSON подключения: %v", err)
		}
	}
	return nil
}

func createInbound(kind proto.Kind, tag string, port int, patch map[string]any) (*db.Inbound, error) {
	info, ok := proto.Get(kind)
	if !ok {
		return nil, fmt.Errorf("неизвестный тип подключения %q", kind)
	}
	if port == 0 {
		port = pickPort(info)
		if port == 0 {
			return nil, fmt.Errorf("не нашёл свободный порт")
		}
	}
	s, err := buildSettings(kind, proto.Settings{}, patch)
	if err != nil {
		return nil, err
	}
	if err := validateInbound(kind, s, port, 0); err != nil {
		return nil, err
	}
	probe := db.Inbound{Kind: string(kind), Settings: s.JSON()}
	if err := core.EnsureForInbound(probe); err != nil {
		return nil, fmt.Errorf("не удалось подготовить ядро: %w", err)
	}
	if strings.TrimSpace(tag) == "" {
		tag = info.Tag
	}
	tag = uniqueTag(tag)
	res, err := db.DB.Exec(`INSERT INTO inbounds (tag, protocol, port, enable, sni, private_key, public_key, short_id, kind, settings)
		VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?)`,
		tag, protocolName(kind), port, s.SNI, s.PrivateKey, s.PublicKey, s.ShortIDs, string(kind), s.JSON())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return db.GetInboundByID(int(id))
}

// inboundMu: подключения создаются и меняются по одному. Проверка «порт занят» идёт до скачивания ядра, а запись в базу после него;
// без блокировки повторные нажатия «Сохранить» за время скачивания все проходили проверку и создавали копии на одном порту.
var inboundMu sync.Mutex

func handleAddInbound(c *gin.Context) {
	inboundMu.Lock()
	defer inboundMu.Unlock()
	rememberHost(c)
	var req inboundRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}
	ib, err := createInbound(proto.Kind(req.Kind), req.Tag, req.Port, req.Settings)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := applyCores(); err != nil {
		// Подключение не прошло проверку ядра – не оставляем его в базе.
		_, _ = db.DB.Exec("DELETE FROM inbounds WHERE id = ?", ib.ID)
		if e2 := applyCores(); e2 != nil {
			log.Printf("Откат подключения %d: повторное применение ядер не удалось: %v", ib.ID, e2)
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Подключение добавлено", "id": ib.ID})
}

// handleQuickSetup – «быстрая настройка» для стандартного режима: набор подключений Xray с безопасными умолчаниями.
// quickSetupKinds – какие подключения создаёт быстрая настройка. По умолчанию рекомендуемый набор:
// REALITY (с Vision у пользователей) и XHTTP, которому при создании достаётся второе имя сайта.
// Каждый лишний порт делает сервер заметнее, поэтому остальное – только по запросу (set = "all").
func quickSetupKinds(set, goos string) []proto.Kind {
	if set != "all" {
		return []proto.Kind{proto.VlessReality, proto.VlessXHTTP}
	}
	// Полный набор как в 3X-UI KIT, без NaiveProxy (нужен домен) и Mieru (отдельный демон): они добавляются вручную.
	kinds := []proto.Kind{proto.VlessReality, proto.VlessXHTTP, proto.VlessWS, proto.TrojanGRPC, proto.VmessWS, proto.SS2022,
		proto.Hysteria2, proto.TUIC, proto.MTProto}
	if goos == "linux" {
		kinds = append(kinds, proto.AWG, proto.AWG3) // сервер AmneziaWG работает только на Linux
	}
	return kinds
}

func handleQuickSetup(c *gin.Context) {
	inboundMu.Lock()
	defer inboundMu.Unlock()
	rememberHost(c)
	var req struct {
		Set string `json:"set"`
	}
	_ = c.ShouldBindJSON(&req) // тело необязательно
	kinds := quickSetupKinds(req.Set, runtime.GOOS)
	existing, _ := db.GetInbounds()
	have := map[string]bool{}
	for _, ib := range existing {
		have[ib.Kind] = true
	}
	var created []int
	var skipped []string
	for _, k := range kinds {
		if have[string(k)] {
			continue
		}
		ib, err := createInbound(k, "", 0, nil)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", k.Title(), err))
			continue
		}
		created = append(created, ib.ID)
	}
	if len(created) == 0 && len(skipped) == 0 {
		c.JSON(http.StatusOK, gin.H{"message": "Все основные подключения уже созданы", "created": 0})
		return
	}
	if err := applyCores(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "created": len(created)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Создано подключений: %d", len(created)), "created": len(created), "skipped": skipped})
}

func handleUpdateInbound(c *gin.Context) {
	inboundMu.Lock()
	defer inboundMu.Unlock()
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
		return
	}
	old, err := db.GetInboundByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Подключение не найдено"})
		return
	}
	var req inboundRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}
	kind := proto.Kind(old.Kind)
	s, err := buildSettings(kind, proto.ParseSettings(old.Settings), req.Settings)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	port := old.Port
	if req.Port != 0 {
		port = req.Port
	}
	tag := old.Tag
	if t := db.CleanName(req.Tag); t != "" && t != old.Tag {
		tag = uniqueTag(t)
	}
	enable := old.Enable
	if req.Enable != nil {
		enable = *req.Enable
	}
	if err := validateInbound(kind, s, port, id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	en := 0
	if enable {
		en = 1
	}
	if _, err := db.DB.Exec(`UPDATE inbounds SET tag = ?, port = ?, enable = ?, sni = ?, private_key = ?, public_key = ?, short_id = ?, settings = ? WHERE id = ?`,
		tag, port, en, s.SNI, s.PrivateKey, s.PublicKey, s.ShortIDs, s.JSON(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения"})
		return
	}
	if err := applyCores(); err != nil {
		// Откат к прежним значениям
		e := 0
		if old.Enable {
			e = 1
		}
		_, _ = db.DB.Exec(`UPDATE inbounds SET tag = ?, port = ?, enable = ?, sni = ?, private_key = ?, public_key = ?, short_id = ?, settings = ? WHERE id = ?`,
			old.Tag, old.Port, e, old.SNI, old.PrivateKey, old.PublicKey, old.ShortID, old.Settings, id)
		if e2 := applyCores(); e2 != nil {
			log.Printf("Откат подключения %d: повторное применение ядер не удалось: %v", id, e2)
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Подключение сохранено"})
}

func handleDeleteInbound(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
		return
	}
	_, _ = db.DB.Exec("DELETE FROM clients WHERE inbound_id = ?", id)
	if _, err := db.DB.Exec("DELETE FROM inbounds WHERE id = ?", id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка удаления"})
		return
	}
	if err := applyCores(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Подключение удалено"})
}
