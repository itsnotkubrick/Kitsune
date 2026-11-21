package sub

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"kitsune/internal/db"
)

// SubSettings – оформление подписки в приложении: название, объявление, кнопки, уведомления об окончании срока.
// Значения передаются заголовками ответа; Happ понимает их все, остальные приложения – основные (название, поддержка).
type SubSettings struct {
	Title          string `json:"title"`            // profile-title, до 25 символов
	Announce       string `json:"announce"`         // announce, до 200 символов
	SupportURL     string `json:"support_url"`      // support-url
	WebURL         string `json:"web_url"`          // profile-web-page-url
	UpdateHours    int    `json:"update_hours"`     // profile-update-interval
	ProviderID     string `json:"provider_id"`      // нужен Happ для расширенных параметров
	ExpireNotice   bool   `json:"expire_notice"`    // sub-expire
	ExpireLink     string `json:"expire_link"`      // sub-expire-button-link
	InfoText       string `json:"info_text"`        // sub-info-text
	InfoColor      string `json:"info_color"`       // red | blue | green
	InfoButtonText string `json:"info_button_text"` // sub-info-button-text
	InfoButtonLink string `json:"info_button_link"` // sub-info-button-link
	HideSettings   bool   `json:"hide_settings"`    // hide-settings
	HappRouting    bool   `json:"happ_routing"`     // передавать Happ правила раздельной маршрутизации
	RoutingUpdated int64  `json:"routing_updated"`  // отметка времени для LastUpdated профиля маршрутизации
}

func DefaultSubSettings() SubSettings {
	return SubSettings{Title: "Kitsune", UpdateHours: 12, InfoColor: "blue", HappRouting: true}
}

func LoadSubSettings() SubSettings {
	s := DefaultSubSettings()
	if raw := db.GetSetting("sub_settings", ""); strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &s)
	}
	return s
}

func SaveSubSettings(s SubSettings) error {
	b, _ := json.Marshal(s)
	return db.SetSetting("sub_settings", string(b))
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

func b64(s string) string { return "base64:" + base64.StdEncoding.EncodeToString([]byte(s)) }

// Validate проверяет значения и приводит их к допустимым пределам.
func (s *SubSettings) Validate() string {
	s.Title = clip(s.Title, 25)
	if s.Title == "" {
		s.Title = "Kitsune"
	}
	s.Announce = clip(s.Announce, 200)
	s.InfoText = clip(s.InfoText, 200)
	s.InfoButtonText = clip(s.InfoButtonText, 25)
	if s.UpdateHours < 1 || s.UpdateHours > 168 {
		s.UpdateHours = 12
	}
	switch s.InfoColor {
	case "red", "blue", "green":
	default:
		s.InfoColor = "blue"
	}
	for name, v := range map[string]string{"поддержки": s.SupportURL, "страницы": s.WebURL, "кнопки продления": s.ExpireLink, "информационной кнопки": s.InfoButtonLink} {
		if v = strings.TrimSpace(v); v != "" && !strings.HasPrefix(v, "https://") && !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "tg://") {
			return "Ссылка " + name + " должна начинаться с https://"
		}
	}
	return ""
}

// ApplyHeaders добавляет заголовки подписки. happ – запрос пришёл от Happ: ему отдаём расширенный набор.
func (s SubSettings) ApplyHeaders(h http.Header, happ bool, routing ClientRouting) {
	h.Set("Profile-Title", b64(s.Title))
	h.Set("Profile-Update-Interval", strconv.Itoa(s.UpdateHours))
	if s.SupportURL != "" {
		h.Set("Support-Url", strings.TrimSpace(s.SupportURL))
	}
	if s.WebURL != "" {
		h.Set("Profile-Web-Page-Url", strings.TrimSpace(s.WebURL))
	}
	if s.Announce != "" {
		h.Set("Announce", b64(s.Announce))
	}
	if !happ {
		return
	}
	if s.ProviderID != "" {
		h.Set("Providerid", s.ProviderID)
		if s.ExpireNotice {
			h.Set("Sub-Expire", "1")
			if s.ExpireLink != "" {
				h.Set("Sub-Expire-Button-Link", s.ExpireLink)
			}
		}
		if s.InfoText != "" {
			h.Set("Sub-Info-Text", s.InfoText)
			h.Set("Sub-Info-Color", s.InfoColor)
			if s.InfoButtonText != "" {
				h.Set("Sub-Info-Button-Text", s.InfoButtonText)
				h.Set("Sub-Info-Button-Link", s.InfoButtonLink)
			}
		}
		if s.HideSettings {
			h.Set("Hide-Settings", "1")
		}
	}
	if s.HappRouting {
		if link := HappRoutingLink(routing, s.RoutingUpdated); link != "" {
			h.Set("Routing", link)
		}
	}
}

func happEntry(r Rule) string {
	v := strings.TrimSpace(r.Value)
	switch strings.ToUpper(r.Type) {
	case "DOMAIN":
		return "full:" + v
	case "DOMAIN-SUFFIX":
		return "domain:" + v
	case "DOMAIN-KEYWORD":
		return "keyword:" + v
	case "GEOSITE":
		return "geosite:" + v
	case "GEOIP":
		return "geoip:" + strings.ToLower(v)
	}
	return v // IP-CIDR
}

func isIPRule(r Rule) bool {
	switch strings.ToUpper(r.Type) {
	case "IP-CIDR", "IP-CIDR6", "GEOIP":
		return true
	}
	return false
}

// HappRoutingProfile превращает раздельную маршрутизацию в профиль Happ (ключи – по документации Happ).
func HappRoutingProfile(c ClientRouting, updated int64) map[string]any {
	rt := c.Compile()
	if !rt.Enable {
		return nil
	}
	var directSites, directIP, proxySites, proxyIP, blockSites, blockIP []string
	for _, r := range rt.Rules {
		e := happEntry(r)
		ip := isIPRule(r)
		switch strings.ToUpper(r.Action) {
		case "DIRECT":
			if ip {
				directIP = append(directIP, e)
			} else {
				directSites = append(directSites, e)
			}
		case "REJECT":
			if ip {
				blockIP = append(blockIP, e)
			} else {
				blockSites = append(blockSites, e)
			}
		default:
			if ip {
				proxyIP = append(proxyIP, e)
			} else {
				proxySites = append(proxySites, e)
			}
		}
	}
	directIP = append([]string{"geoip:private"}, directIP...)
	global := "true"
	if strings.EqualFold(rt.Final, "DIRECT") {
		global = "false" // всё, что не попало в списки, идёт напрямую
	}
	p := map[string]any{
		"Name": "Kitsune", "GlobalProxy": global, "DomainStrategy": "IPIfNonMatch", "FakeDNS": "false",
		"LastUpdated": strconv.FormatInt(updated, 10),
		"DirectSites": directSites, "DirectIp": directIP, "ProxySites": proxySites, "ProxyIp": proxyIP,
		"BlockSites": blockSites, "BlockIp": blockIP,
	}
	return p
}

// HappRoutingLink – ссылка happ://routing/onadd/<base64>, которую приложение выполнит сразу при получении подписки.
func HappRoutingLink(c ClientRouting, updated int64) string {
	p := HappRoutingProfile(c, updated)
	if p == nil {
		return ""
	}
	raw, _ := json.Marshal(p)
	return "happ://routing/onadd/" + base64.StdEncoding.EncodeToString(raw)
}
