package core

import (
	"encoding/json"
	"strings"

	"kitsune/internal/db"
)

// XraySettings – глобальные параметры ядра Xray: журнал, DNS, маршрутизация, политики, исходящие.
// Хранятся в БД (ключ xray_settings) и применяются при каждой сборке config.json.
type XraySettings struct {
	// Журнал
	LogLevel  string `json:"log_level"`
	AccessLog bool   `json:"access_log"`

	// DNS
	DNSEnable       bool     `json:"dns_enable"`
	DNSServers      []string `json:"dns_servers"`
	DNSStrategy     string   `json:"dns_strategy"`
	DNSDisableCache bool     `json:"dns_disable_cache"`

	// Маршрутизация (серверная: что делать с трафиком клиентов)
	DomainStrategy  string   `json:"domain_strategy"`
	BlockPrivate    bool     `json:"block_private"`
	BlockBittorrent bool     `json:"block_bittorrent"`
	BlockAds        bool     `json:"block_ads"`
	BlockDomains    []string `json:"block_domains"`
	BlockIPs        []string `json:"block_ips"`
	DirectDomains   []string `json:"direct_domains"`
	DirectIPs       []string `json:"direct_ips"`
	RoutingExtra    string   `json:"routing_extra"` // JSON-массив правил Xray, добавляется перед остальными

	// Исходящие
	FreedomStrategy string `json:"freedom_strategy"` // AsIs | UseIP | UseIPv4 | UseIPv6
	FreedomFragment bool   `json:"freedom_fragment"`
	OutboundsExtra  string `json:"outbounds_extra"` // JSON-массив дополнительных исходящих

	// Политики (секунды)
	PolicyHandshake    int `json:"policy_handshake"`
	PolicyConnIdle     int `json:"policy_conn_idle"`
	PolicyUplinkOnly   int `json:"policy_uplink_only"`
	PolicyDownlinkOnly int `json:"policy_downlink_only"`
	PolicyBufferSize   int `json:"policy_buffer_size"` // КБ

	// Произвольный JSON, вливаемый в готовый config.json
	RawPatch string `json:"raw_patch"`
}

func DefaultXraySettings() XraySettings {
	return XraySettings{
		LogLevel:        "warning",
		DNSServers:      []string{"1.1.1.1", "8.8.8.8"},
		DNSStrategy:     "UseIP",
		DomainStrategy:  "AsIs",
		BlockPrivate:    true,
		FreedomStrategy: "AsIs",
		PolicyHandshake: 4,
		PolicyConnIdle:  300,
	}
}

func LoadXraySettings() XraySettings {
	s := DefaultXraySettings()
	if db.DB == nil {
		return s
	}
	if raw := db.GetSetting("xray_settings", ""); strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &s)
	}
	return s
}

func SaveXraySettings(s XraySettings) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.SetSetting("xray_settings", string(b))
}
