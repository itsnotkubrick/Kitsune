package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"kitsune/internal/db"
	"kitsune/internal/pro"
	"kitsune/internal/proto"
	"kitsune/internal/site"
	"kitsune/internal/stub"
)

const ConfigPath = "config.json"

// XrayProc – ядро Xray под присмотром панели.
var XrayProc = NewProc("xray")

// FindBinary ищет бинарник ядра: ./bin, /usr/local/bin, PATH.
func FindBinary(name string) string {
	cands := []string{filepath.Join(BinDir, name), filepath.Join("/usr/local/bin", name), filepath.Join("/opt/kitsune/bin", name)}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

func XrayBinary() string { return FindBinary("xray") }

// assetEnv указывает Xray, где лежат geoip.dat и geosite.dat.
func assetEnv(bin string) []string {
	return []string{"XRAY_LOCATION_ASSET=" + filepath.Dir(bin)}
}

// PublicEnv возвращает адрес сервера для сертификатов и ссылок.
func PublicEnv() proto.Env {
	return proto.Env{Host: db.GetSetting("public_host", ""), StubID: db.GetSetting("stub_site", stub.DefaultID), MasqURL: site.LocalURL(),
		Single: db.GetSetting("port_mode", "separate") == "single443"}
}

// BuildXrayConfig собирает config.json из подключений, активных пользователей и глобальных настроек.
func BuildXrayConfig(env proto.Env) (proto.M, error) {
	cfg := LoadXraySettings()
	inbounds, err := db.GetInbounds()
	if err != nil {
		return nil, err
	}
	users, err := db.GetUsers()
	if err != nil {
		return nil, err
	}

	gm := db.GroupMap()
	list := []proto.M{{
		"tag": "api", "listen": "127.0.0.1", "port": 10085, "protocol": "dokodemo-door",
		"settings": proto.M{"address": "127.0.0.1"},
	}}
	for _, ib := range inbounds {
		if !ib.Enable {
			continue
		}
		var creds []proto.Cred
		for _, u := range users {
			if u.Active() && db.Allowed(gm, u, ib.ID) {
				creds = append(creds, proto.Cred{Email: db.ClientEmail(u.Name, ib.Tag), User: u})
			}
		}
		x, err := proto.BuildXray(ib, creds, env)
		if err != nil {
			return nil, fmt.Errorf("подключение %s: %w", ib.Tag, err)
		}
		if x != nil {
			list = append(list, x)
		}
	}

	// Журнал
	logCfg := proto.M{"loglevel": cfg.LogLevel}
	if cfg.AccessLog {
		_ = os.MkdirAll(LogDir, 0o755)
		abs, _ := filepath.Abs(filepath.Join(LogDir, "xray-access.log"))
		logCfg["access"] = abs
	}

	// Политики: statsUser* нужны, чтобы Xray считал трафик каждого пользователя.
	lvl0 := proto.M{"statsUserUplink": true, "statsUserDownlink": true, "statsUserOnline": true}
	if cfg.PolicyHandshake > 0 {
		lvl0["handshake"] = cfg.PolicyHandshake
	}
	if cfg.PolicyConnIdle > 0 {
		lvl0["connIdle"] = cfg.PolicyConnIdle
	}
	if cfg.PolicyUplinkOnly > 0 {
		lvl0["uplinkOnly"] = cfg.PolicyUplinkOnly
	}
	if cfg.PolicyDownlinkOnly > 0 {
		lvl0["downlinkOnly"] = cfg.PolicyDownlinkOnly
	}
	if cfg.PolicyBufferSize > 0 {
		lvl0["bufferSize"] = cfg.PolicyBufferSize
	}

	freedom := proto.M{"protocol": "freedom", "tag": "direct"}
	fs := proto.M{}
	if cfg.FreedomStrategy != "" && cfg.FreedomStrategy != "AsIs" {
		fs["domainStrategy"] = cfg.FreedomStrategy
	}
	if cfg.FreedomFragment {
		fs["fragment"] = proto.M{"packets": "tlshello", "length": "100-200", "interval": "10-20"}
	}
	if len(fs) > 0 {
		freedom["settings"] = fs
	}
	outbounds := []proto.M{freedom, {"protocol": "blackhole", "tag": "blocked"}}
	if strings.TrimSpace(cfg.OutboundsExtra) != "" {
		var extra []proto.M
		if err := json.Unmarshal([]byte(cfg.OutboundsExtra), &extra); err != nil {
			return nil, fmt.Errorf("дополнительные исходящие: %w", err)
		}
		outbounds = append(outbounds, extra...)
	}

	proOut, proRules, perr := pro.XrayParts()
	if perr != nil {
		return nil, perr
	}
	outbounds = append(outbounds, proOut...)

	// Маршрутизация
	rules := []proto.M{{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"}}
	rules = append(rules, proRules...)
	if strings.TrimSpace(cfg.RoutingExtra) != "" {
		var extra []proto.M
		if err := json.Unmarshal([]byte(cfg.RoutingExtra), &extra); err != nil {
			return nil, fmt.Errorf("свои правила маршрутизации: %w", err)
		}
		rules = append(rules, extra...)
	}
	if cfg.BlockPrivate {
		rules = append(rules, proto.M{"type": "field", "ip": []string{"geoip:private"}, "outboundTag": "blocked"})
	}
	if cfg.BlockBittorrent {
		rules = append(rules, proto.M{"type": "field", "protocol": []string{"bittorrent"}, "outboundTag": "blocked"})
	}
	if cfg.BlockAds {
		rules = append(rules, proto.M{"type": "field", "domain": []string{"geosite:category-ads-all"}, "outboundTag": "blocked"})
	}
	if len(cfg.BlockDomains) > 0 {
		rules = append(rules, proto.M{"type": "field", "domain": cfg.BlockDomains, "outboundTag": "blocked"})
	}
	if len(cfg.BlockIPs) > 0 {
		rules = append(rules, proto.M{"type": "field", "ip": cfg.BlockIPs, "outboundTag": "blocked"})
	}
	if len(cfg.DirectDomains) > 0 {
		rules = append(rules, proto.M{"type": "field", "domain": cfg.DirectDomains, "outboundTag": "direct"})
	}
	if len(cfg.DirectIPs) > 0 {
		rules = append(rules, proto.M{"type": "field", "ip": cfg.DirectIPs, "outboundTag": "direct"})
	}

	out := proto.M{
		"log":       logCfg,
		"api":       proto.M{"tag": "api", "services": []string{"StatsService", "RoutingService"}},
		"stats":     proto.M{},
		"policy":    proto.M{"levels": proto.M{"0": lvl0}, "system": proto.M{"statsInboundUplink": true, "statsInboundDownlink": true, "statsOutboundUplink": true, "statsOutboundDownlink": true}},
		"inbounds":  list,
		"outbounds": outbounds,
		"routing":   proto.M{"domainStrategy": cfg.DomainStrategy, "rules": rules},
	}
	if cfg.DNSEnable && len(cfg.DNSServers) > 0 {
		dns := proto.M{"servers": cfg.DNSServers, "queryStrategy": cfg.DNSStrategy}
		if cfg.DNSDisableCache {
			dns["disableCache"] = true
		}
		out["dns"] = dns
	}
	if err := applyRawPatch(out, cfg.RawPatch); err != nil {
		return nil, err
	}
	return out, nil
}

// applyRawPatch накладывает свой JSON администратора на готовый конфиг. Пути журналов и служебный API Xray им не переопределяются:
// через них можно писать в произвольные файлы (например, при восстановлении чужой копии) или открыть управление ядром.
func applyRawPatch(out proto.M, raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var patch proto.M
	if err := json.Unmarshal([]byte(raw), &patch); err != nil {
		return fmt.Errorf("свой JSON конфига: %w", err)
	}
	if lg, ok := patch["log"].(map[string]any); ok {
		delete(lg, "access")
		delete(lg, "error")
	}
	delete(patch, "api")
	mergeMap(out, patch)
	return nil
}

func mergeMap(dst, patch proto.M) {
	for k, v := range patch {
		pm, pok := v.(map[string]any)
		dm, dok := dst[k].(proto.M)
		if pok && dok {
			mergeMap(dm, pm)
			continue
		}
		dst[k] = v
	}
}

// TestXrayConfig проверяет файл конфига самим Xray (run -test).
func TestXrayConfig(path string) error {
	bin := XrayBinary()
	if bin == "" {
		return nil // ядра нет – проверять нечем, конфиг всё равно сохраним
	}
	cmd := exec.Command(bin, "run", "-test", "-c", path)
	cmd.Env = append(os.Environ(), assetEnv(bin)...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		return errors.New(lastLines(lines, 3))
	}
	return nil
}

func lastLines(l []string, n int) string {
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "; ")
}

// ApplyXray собирает конфиг, проверяет его, атомарно подменяет файл и (пере)запускает ядро.
// При ошибке проверки прежний рабочий конфиг остаётся нетронутым.
func ApplyXray() error {
	cfg, err := BuildXrayConfig(PublicEnv())
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := "config.new.json"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := TestXrayConfig(tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("Xray не принял конфиг: %w", err)
	}
	if err := os.Rename(tmp, ConfigPath); err != nil {
		return err
	}
	return RestartXray()
}

// RestartXray запускает или перезапускает ядро с текущим config.json.
func RestartXray() error {
	bin := XrayBinary()
	if bin == "" {
		return errors.New("ядро Xray не установлено")
	}
	abs, _ := filepath.Abs(ConfigPath)
	return XrayProc.Start(bin, []string{"run", "-c", abs}, assetEnv(bin), "")
}

// QueryTrafficStats читает счётчики трафика пользователей и обнуляет их.
type StatItem struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}

func QueryTrafficStats() ([]StatItem, error) {
	bin := XrayBinary()
	if bin == "" || !XrayProc.Running() {
		return nil, errors.New("ядро не запущено")
	}
	cmd := exec.Command(bin, "api", "statsquery", "--server=127.0.0.1:10085", "-reset=true")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	var resp struct {
		Stat []StatItem `json:"stat"`
	}
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		return nil, err
	}
	return resp.Stat, nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// ApplyAll приводит все ядра в соответствие с БД. Ошибки разных ядер собираются вместе:
// сбой одного (например, не установлен sing-box) не мешает остальным.
var applyMu sync.Mutex

func ApplyAll() error {
	applyMu.Lock() // одновременные применения (запрос, монитор лимитов, сертификат) не должны мешать друг другу
	defer applyMu.Unlock()
	type step struct {
		name string
		fn   func() error
	}
	core := []step{{"Xray", ApplyXray}, {"sing-box", ApplySingbox}, {"MASQUE", ApplyMasque}, {"MTProto", ApplyMTG}, {"Mieru", ApplyMita}, {"AmneziaWG", ApplyAWG}}
	router := step{"Маршрутизатор 443", ApplyRouter}
	// Порт 443 переходит от ядер к маршрутизатору и обратно: освобождающий шаг идёт первым.
	steps := append([]step{router}, core...)
	if PublicEnv().Single {
		steps = append(core, router)
	}
	var errs []string
	// Сертификаты Let's Encrypt: домены и проверка на порту 80 готовятся до сборки конфигов ядер.
	if err := ConfigureACME(); err != nil {
		errs = append(errs, "Let's Encrypt: "+err.Error())
	}
	// Ядра, которых не хватает подключениям, докачиваются автоматически (с проверкой SHA-256).
	if inbounds, err := db.GetInbounds(); err == nil {
		tried := map[string]bool{}
		for _, ib := range inbounds {
			id := CoreForInbound(ib)
			if !ib.Enable || id == "" || tried[id] {
				continue
			}
			tried[id] = true
			if err := ensureCore(id); err != nil {
				errs = append(errs, "установка ядра "+id+": "+err.Error())
			}
		}
	}
	for _, st := range steps {
		if err := st.fn(); err != nil {
			errs = append(errs, st.name+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// StartAll запускает все ядра при старте панели.
func StartAll() {
	if err := ApplyAll(); err != nil {
		log.Printf("Запуск ядер: %v", err)
		if _, e := os.Stat(ConfigPath); e == nil && XrayBinary() != "" && !XrayProc.Running() {
			_ = RestartXray()
		}
	}
}

// Statuses – состояние всех ядер для дашборда.
func Statuses() []Status {
	list := []Status{XrayProc.Status(), SingboxProc.Status(), MasqueProc.Status(), MitaProc.Status()}
	for _, p := range mtgList() {
		list = append(list, p.Status())
	}
	return list
}

// Component – описание ядра для интерфейса.
type Component struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Used      string `json:"used"`
	Version   string `json:"version"`
	Installed bool   `json:"installed"`
	Running   bool   `json:"running"`
	Platform  bool   `json:"platform"` // есть сборка под эту ОС
	Needed    bool   `json:"needed"`   // есть включённые подключения, которым нужно это ядро
}

// Components перечисляет ядра с признаками установки.
func Components() []Component {
	has := func(m map[string]Asset) bool { _, ok := m[platform()]; return ok }
	needed := map[string]bool{}
	if inbounds, err := db.GetInbounds(); err == nil {
		for _, ib := range inbounds {
			if ib.Enable {
				switch ib.Kind {
				case string(proto.AWG), string(proto.AWG3):
					needed["awg"] = true
				default:
					needed[CoreForInbound(ib)] = true
				}
			}
		}
	}
	list := []Component{
		{ID: "xray", Title: "Xray", Used: "VLESS, VMess, Trojan, Shadowsocks 2022, Hysteria2", Version: InstalledVersion("xray"),
			Installed: XrayBinary() != "", Running: XrayProc.Running(), Platform: has(xrayAssets)},
		{ID: "singbox", Title: "sing-box", Used: "TUIC v5, NaiveProxy", Version: InstalledVersion("singbox"),
			Installed: SingboxBinary() != "", Running: SingboxProc.Running(), Platform: has(singboxAssets)},
		{ID: "masque", Title: "sing-box (MASQUE)", Used: "MASQUE (CONNECT-IP), последняя версия", Version: InstalledVersion("masque"),
			Installed: MasqueBinary() != "", Running: MasqueProc.Running(), Platform: has(masqueAssets)},
		{ID: "mtg", Title: "mtg", Used: "MTProto (Telegram)", Version: InstalledVersion("mtg"),
			Installed: MTGBinary() != "", Running: anyRunning(), Platform: has(mtgAssets)},
		{ID: "mita", Title: "mita", Used: "Mieru", Version: InstalledVersion("mita"),
			Installed: MitaBinary() != "", Running: MitaProc.Running(), Platform: has(mitaAssets)},
		{ID: "telemt", Title: "telemt", Used: "MTProto с личными секретами", Version: InstalledVersion("telemt"),
			Installed: TelemtBinary() != "", Running: anyRunning(), Platform: has(telemtAssets)},
		{ID: "awg", Title: "amneziawg-go", Used: "AmneziaWG и AmneziaWG 3.1 (встроено в панель)", Version: "встроено",
			Installed: true, Running: awgRunning(), Platform: runtime.GOOS == "linux"},
	}
	for i := range list {
		list[i].Needed = needed[list[i].ID]
	}
	return list
}

func anyRunning() bool {
	for _, p := range mtgList() {
		if p.Running() {
			return true
		}
	}
	return false
}

// InstallComponent ставит ядро по идентификатору.
func InstallComponent(id string) error {
	switch id {
	case "xray":
		return InstallXray()
	case "singbox":
		return InstallSingbox()
	case "masque":
		return InstallMasque()
	case "mtg":
		return InstallMTG()
	case "mita":
		return InstallMita()
	case "telemt":
		return InstallTelemt()
	}
	return fmt.Errorf("неизвестное ядро %q", id)
}

// CoreFor возвращает ядро, нужное типу подключения (идентификатор компонента).
func CoreFor(kind proto.Kind) string {
	info, ok := proto.Get(kind)
	if !ok {
		return ""
	}
	switch info.Core {
	case proto.CoreXray:
		return "xray"
	case proto.CoreSingbox:
		return "singbox"
	case proto.CoreMasque:
		return "masque"
	case proto.CoreMTG:
		return "mtg"
	case proto.CoreMita:
		return "mita"
	}
	return ""
}

// CoreForInbound – ядро конкретного подключения (MTProto зависит от выбранного движка).
func CoreForInbound(ib db.Inbound) string {
	if ib.Kind == string(proto.MTProto) && proto.ParseSettings(ib.Settings).Engine == "telemt" {
		return "telemt"
	}
	return CoreFor(proto.Kind(ib.Kind))
}

// EnsureForInbound докачивает ядро, нужное подключению.
func EnsureForInbound(ib db.Inbound) error { return ensureCore(CoreForInbound(ib)) }

// EnsureFor докачивает ядро, нужное типу подключения, если его ещё нет.
func EnsureFor(kind proto.Kind) error { return ensureCore(CoreFor(kind)) }

func ensureCore(id string) error {
	if id == "" {
		return nil
	}
	for _, c := range Components() {
		if c.ID == id && !c.Installed {
			if !c.Platform {
				return fmt.Errorf("%s не поддерживается на этой системе (%s)", c.Title, platform())
			}
			return InstallComponent(id)
		}
	}
	return nil
}

// StopAll останавливает все ядра (при остановке панели).
func StopAll() {
	XrayProc.Stop()
	SingboxProc.Stop()
	MasqueProc.Stop()
	MitaProc.Stop()
	sniRouter.stop()
	stopAWG()
	for _, p := range mtgList() {
		p.Stop()
	}
}
