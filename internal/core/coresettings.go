package core

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"

	"kitsune/internal/db"
)

// Настройки ядер, кроме Xray (у него свои, см. XraySettings). Хранятся одним JSON в БД (ключ core_settings).
// Значения по умолчанию воспроизводят прежнее поведение панели: пока ничего не менялось, конфиги ядер те же.
// Имена и допустимые значения взяты из документации ядер: sing-box (log, listen), mtg (example.config.toml),
// mita (server-install), telemt (CONFIG_PARAMS), amneziawg-go (уровни журнала устройства).

type SingboxSettings struct {
	LogLevel     string `json:"log_level"`     // trace, debug, info, warn, error, fatal, panic
	LogTimestamp bool   `json:"log_timestamp"` // время в строках журнала
	TCPFastOpen  bool   `json:"tcp_fast_open"` // TCP Fast Open у NaiveProxy (Linux 3.7+)
}

type MTGSettings struct {
	Debug                  bool   `json:"debug"`                     // подробный журнал
	DNS                    string `json:"dns"`                       // резолвер: IP, https://…, tls://…; пусто – системный
	TimeoutIdle            string `json:"timeout_idle"`              // простой соединения, по умолчанию 5m
	TimeoutHandshake       string `json:"timeout_handshake"`         // рукопожатие, по умолчанию 10s
	ToleratTimeSkewness    string `json:"tolerate_time_skewness"`    // окно часов клиента, по умолчанию 3s
	AllowFallbackUnknownDC bool   `json:"allow_fallback_unknown_dc"` // неизвестные DC отправлять в любой
	AntiReplay             bool   `json:"anti_replay"`               // защита от повторов (по умолчанию включена)
	Blocklist              bool   `json:"blocklist"`                 // чёрный список адресов FireHOL (по умолчанию включён)
}

type MitaSettings struct {
	LoggingLevel      string `json:"logging_level"`       // INFO, WARN, ERROR, DEBUG
	DNSDualStack      string `json:"dns_dual_stack"`      // пусто – не писать; иначе USE_FIRST_IP, PREFER_IPv4, PREFER_IPv6, ONLY_IPv4, ONLY_IPv6
	UserHintMandatory bool   `json:"user_hint_mandatory"` // не пускать старые клиенты Mieru без подсказки пользователя
}

type TelemtSettings struct {
	LogLevel       string `json:"log_level"`        // debug, verbose, normal, silent
	UseMiddleProxy bool   `json:"use_middle_proxy"` // false – напрямую к дата-центрам Telegram
	IPv6           bool   `json:"ipv6"`
	Prefer         int    `json:"prefer"`          // 4 или 6
	MaxConnections int    `json:"max_connections"` // 0 – без предела
}

type AWGSettings struct {
	LogLevel string `json:"log_level"` // silent, error, verbose
}

type CoreSettings struct {
	Singbox SingboxSettings `json:"singbox"`
	MTG     MTGSettings     `json:"mtg"`
	Mita    MitaSettings    `json:"mita"`
	Telemt  TelemtSettings  `json:"telemt"`
	AWG     AWGSettings     `json:"awg"`
}

func DefaultCoreSettings() CoreSettings {
	return CoreSettings{
		Singbox: SingboxSettings{LogLevel: "warn", LogTimestamp: true},
		MTG:     MTGSettings{AntiReplay: true, Blocklist: true},
		Mita:    MitaSettings{LoggingLevel: "INFO"},
		Telemt:  TelemtSettings{LogLevel: "normal", UseMiddleProxy: true, Prefer: 4, MaxConnections: 10000},
		AWG:     AWGSettings{LogLevel: "error"},
	}
}

func LoadCoreSettings() CoreSettings {
	s := DefaultCoreSettings()
	if db.DB == nil {
		return s
	}
	if raw := db.GetSetting("core_settings", ""); strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &s)
	}
	return s.sanitized()
}

func SaveCoreSettings(s CoreSettings) error {
	b, err := json.Marshal(s.sanitized())
	if err != nil {
		return err
	}
	return db.SetSetting("core_settings", string(b))
}

var durRe = regexp.MustCompile(`^[1-9][0-9]{0,4}(ms|s|m|h)$`)

func oneOf(v string, def string, allowed ...string) string {
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	return def
}

// ValidateCoreSettings проверяет значения, пришедшие из интерфейса: неверное значение – ошибка, а не молчаливая замена.
func (s CoreSettings) Validate() error {
	d := DefaultCoreSettings()
	if oneOf(s.Singbox.LogLevel, "", "trace", "debug", "info", "warn", "error", "fatal", "panic") == "" {
		return fmt.Errorf("sing-box: уровень журнала %q не поддерживается", s.Singbox.LogLevel)
	}
	for name, v := range map[string]string{"простой": s.MTG.TimeoutIdle, "рукопожатие": s.MTG.TimeoutHandshake, "допуск часов": s.MTG.ToleratTimeSkewness} {
		if v != "" && !durRe.MatchString(v) {
			return fmt.Errorf("mtg: %s: нужна длительность вида 30s, 5m или 1h", name)
		}
	}
	if v := s.MTG.DNS; v != "" && !validMTGDNS(v) {
		return fmt.Errorf("mtg: DNS: нужен IP-адрес или адрес вида https://1.1.1.1, tls://1.1.1.1")
	}
	if oneOf(s.Mita.LoggingLevel, "", "INFO", "WARN", "ERROR", "DEBUG") == "" {
		return fmt.Errorf("mita: уровень журнала %q не поддерживается", s.Mita.LoggingLevel)
	}
	if v := s.Mita.DNSDualStack; v != "" && oneOf(v, "", "USE_FIRST_IP", "PREFER_IPv4", "PREFER_IPv6", "ONLY_IPv4", "ONLY_IPv6") == "" {
		return fmt.Errorf("mita: dualStack %q не поддерживается", v)
	}
	if oneOf(s.Telemt.LogLevel, "", "debug", "verbose", "normal", "silent") == "" {
		return fmt.Errorf("telemt: уровень журнала %q не поддерживается", s.Telemt.LogLevel)
	}
	if s.Telemt.Prefer != 4 && s.Telemt.Prefer != 6 {
		return fmt.Errorf("telemt: предпочтение адресов: 4 или 6")
	}
	if s.Telemt.MaxConnections < 0 || s.Telemt.MaxConnections > 1000000 {
		return fmt.Errorf("telemt: предел соединений от 0 до 1000000")
	}
	if oneOf(s.AWG.LogLevel, "", "silent", "error", "verbose") == "" {
		return fmt.Errorf("AmneziaWG: уровень журнала %q не поддерживается", s.AWG.LogLevel)
	}
	_ = d
	return nil
}

func validMTGDNS(v string) bool {
	if net.ParseIP(v) != nil {
		return true
	}
	for _, p := range []string{"https://", "tls://"} {
		if strings.HasPrefix(v, p) {
			h := strings.TrimPrefix(v, p)
			if i := strings.IndexAny(h, "/"); i >= 0 {
				h = h[:i]
			}
			h = strings.TrimSuffix(h, ":853")
			return net.ParseIP(h) != nil || regexp.MustCompile(`^[a-zA-Z0-9.-]{1,253}$`).MatchString(h)
		}
	}
	return false
}

// sanitized подставляет умолчания вместо пустых или неверных значений при чтении из БД (повреждённая запись не роняет ядра).
func (s CoreSettings) sanitized() CoreSettings {
	d := DefaultCoreSettings()
	s.Singbox.LogLevel = oneOf(s.Singbox.LogLevel, d.Singbox.LogLevel, "trace", "debug", "info", "warn", "error", "fatal", "panic")
	for _, p := range []*string{&s.MTG.TimeoutIdle, &s.MTG.TimeoutHandshake, &s.MTG.ToleratTimeSkewness} {
		if *p != "" && !durRe.MatchString(*p) {
			*p = ""
		}
	}
	if s.MTG.DNS != "" && !validMTGDNS(s.MTG.DNS) {
		s.MTG.DNS = ""
	}
	s.Mita.LoggingLevel = oneOf(s.Mita.LoggingLevel, d.Mita.LoggingLevel, "INFO", "WARN", "ERROR", "DEBUG")
	s.Mita.DNSDualStack = oneOf(s.Mita.DNSDualStack, "", "USE_FIRST_IP", "PREFER_IPv4", "PREFER_IPv6", "ONLY_IPv4", "ONLY_IPv6")
	s.Telemt.LogLevel = oneOf(s.Telemt.LogLevel, d.Telemt.LogLevel, "debug", "verbose", "normal", "silent")
	if s.Telemt.Prefer != 4 && s.Telemt.Prefer != 6 {
		s.Telemt.Prefer = 4
	}
	if s.Telemt.MaxConnections < 0 || s.Telemt.MaxConnections > 1000000 {
		s.Telemt.MaxConnections = d.Telemt.MaxConnections
	}
	s.AWG.LogLevel = oneOf(s.AWG.LogLevel, d.AWG.LogLevel, "silent", "error", "verbose")
	return s
}
