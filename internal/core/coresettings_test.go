package core

import (
	"strings"
	"testing"

	"kitsune/internal/db"
	"kitsune/internal/proto"
)

func TestCoreSettingsDefaultsKeepOldConfigs(t *testing.T) {
	d := DefaultCoreSettings()
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	ib := db.Inbound{ID: 5, Kind: string(proto.MTProto), Port: 8447}
	got := mtgConfigWith(ib, proto.Settings{Secret: "ee00"}, d.MTG)
	for _, bad := range []string{"debug", "[network", "[defense", "tolerate", "fallback"} {
		if strings.Contains(got, bad) {
			t.Errorf("умолчания не должны писать %q:\n%s", bad, got)
		}
	}
}

func TestMTGSettingsWritten(t *testing.T) {
	cs := MTGSettings{Debug: true, DNS: "https://1.1.1.1", TimeoutIdle: "10m", TimeoutHandshake: "15s", ToleratTimeSkewness: "5s",
		AllowFallbackUnknownDC: true, AntiReplay: false, Blocklist: false}
	got := mtgConfigWith(db.Inbound{ID: 5, Port: 8447}, proto.Settings{Secret: "ee00"}, cs)
	for _, want := range []string{"debug = true", "allow-fallback-on-unknown-dc = true", `tolerate-time-skewness = "5s"`,
		"[network]\ndns = \"https://1.1.1.1\"", "[network.timeout]\nidle = \"10m\"\nhandshake = \"15s\"",
		"[defense.anti-replay]\nenabled = false", "[defense.blocklist]\nenabled = false"} {
		if !strings.Contains(got, want) {
			t.Errorf("нет %q:\n%s", want, got)
		}
	}
	// ключи верхнего уровня должны стоять до первой таблицы, иначе TOML отнесёт их к таблице
	if i, j := strings.Index(got, "debug = true"), strings.Index(got, "["); i > j {
		t.Errorf("debug после первой таблицы:\n%s", got)
	}
}

func TestCoreSettingsValidate(t *testing.T) {
	for name, mut := range map[string]func(*CoreSettings){
		"singbox уровень":  func(s *CoreSettings) { s.Singbox.LogLevel = "loud" },
		"mtg длительность": func(s *CoreSettings) { s.MTG.TimeoutIdle = "5 минут" },
		"mtg dns":          func(s *CoreSettings) { s.MTG.DNS = "ftp://x" },
		"mita уровень":     func(s *CoreSettings) { s.Mita.LoggingLevel = "info" },
		"mita dualStack":   func(s *CoreSettings) { s.Mita.DNSDualStack = "PREFER_IPV4" },
		"telemt prefer":    func(s *CoreSettings) { s.Telemt.Prefer = 5 },
		"telemt предел":    func(s *CoreSettings) { s.Telemt.MaxConnections = -1 },
		"awg уровень":      func(s *CoreSettings) { s.AWG.LogLevel = "trace" },
	} {
		s := DefaultCoreSettings()
		mut(&s)
		if s.Validate() == nil {
			t.Errorf("%s: неверное значение принято", name)
		}
	}
	ok := DefaultCoreSettings()
	ok.MTG.DNS, ok.MTG.TimeoutIdle, ok.Mita.DNSDualStack = "tls://9.9.9.9", "90s", "PREFER_IPv4"
	if err := ok.Validate(); err != nil {
		t.Errorf("верные значения отклонены: %v", err)
	}
}

func TestCoreSettingsSanitizedRepairsBrokenRecord(t *testing.T) {
	s := CoreSettings{}.sanitized() // пустая запись целиком
	if s.Singbox.LogLevel != "warn" || s.Mita.LoggingLevel != "INFO" || s.Telemt.Prefer != 4 || s.AWG.LogLevel != "error" || s.Telemt.LogLevel != "normal" {
		t.Errorf("умолчания не подставились: %+v", s)
	}
}

func TestMitaAndTelemtSettings(t *testing.T) {
	// настройки читаются из БД: в тесте БД нет, поэтому проверяем сборку напрямую через умолчания и ручной вызов
	cfg := BuildMitaConfig(db.Inbound{ID: 1, Kind: string(proto.Mieru), Port: 8446, Settings: "{}"}, nil)
	if cfg["loggingLevel"] != "INFO" {
		t.Errorf("loggingLevel: %v", cfg["loggingLevel"])
	}
	if _, has := cfg["dns"]; has {
		t.Error("блок dns не должен писаться по умолчанию")
	}
	if _, has := cfg["advancedSettings"]; has {
		t.Error("advancedSettings не должен писаться по умолчанию")
	}
	tl := BuildTelemtConfig(db.Inbound{ID: 1, Kind: string(proto.MTProto), Port: 8447, Settings: "{}"}, nil, proto.Env{Host: "h"}, "/tmp/t")
	if !strings.Contains(tl, "use_middle_proxy = true") || !strings.Contains(tl, `log_level = "normal"`) || strings.Contains(tl, "max_connections") || strings.Contains(tl, "[network]") {
		t.Errorf("telemt по умолчанию изменился:\n%s", tl)
	}
}
