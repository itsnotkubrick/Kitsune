package core

import (
	"encoding/json"
	"strings"

	"kitsune/internal/acme"
	"kitsune/internal/db"
	"kitsune/internal/proto"
)

// PanelTLS – настройки HTTPS самой панели.
type PanelTLS struct {
	Mode     string `json:"mode"`      // off | self | acme | custom
	Port     int    `json:"port"`      // порт HTTPS (по умолчанию 8443)
	Domain   string `json:"domain"`    // для режима acme
	Email    string `json:"email"`     // контакт Let's Encrypt
	CertFile string `json:"cert_file"` // для режима custom
	KeyFile  string `json:"key_file"`
	Redirect bool   `json:"redirect"` // перенаправлять обычный HTTP на HTTPS
}

func LoadPanelTLS() PanelTLS {
	t := PanelTLS{Mode: "off", Port: 8443}
	if raw := db.GetSetting("panel_tls", ""); strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &t)
	}
	if t.Port == 0 {
		t.Port = 8443
	}
	return t
}

func SavePanelTLS(t PanelTLS) error {
	b, _ := json.Marshal(t)
	if err := db.SetSetting("panel_tls", string(b)); err != nil {
		return err
	}
	if t.Email != "" {
		_ = db.SetSetting("acme_email", t.Email)
	}
	return nil
}

// ACMEDomains – домены, которым нужен сертификат Let's Encrypt: панель и подключения с cert_mode=acme.
func ACMEDomains() []string {
	seen := map[string]bool{}
	var out []string
	add := func(d string) {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	if p := LoadPanelTLS(); p.Mode == "acme" {
		add(p.Domain)
	}
	add(db.GetSetting("selfsteal_domain", "")) // сайт-заглушка на своём домене (REALITY self-steal)
	if inbounds, err := db.GetInbounds(); err == nil {
		for _, ib := range inbounds {
			if !ib.Enable {
				continue
			}
			s := proto.ParseSettings(ib.Settings)
			if s.CertMode == "acme" {
				add(s.SNI)
			}
		}
	}
	return out
}

// ConfigureACME передаёт менеджеру сертификатов список доменов и включает проверку на порту 80, когда она нужна.
func ConfigureACME() error {
	domains := ACMEDomains()
	acme.Configure(db.GetSetting("acme_email", ""), domains)
	if len(domains) == 0 {
		acme.StopChallenge()
		return nil
	}
	return acme.StartChallenge(":80")
}

// RefreshACME перевыгружает сертификаты в файлы (и продлевает, если пора). true – какой-то сертификат изменился.
func RefreshACME() bool {
	changed := false
	for _, d := range ACMEDomains() {
		if _, _, ch, err := acme.Files(d); err == nil && ch {
			changed = true
		}
	}
	return changed
}
