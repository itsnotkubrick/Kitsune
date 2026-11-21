package sub

import (
	"encoding/json"
	"strings"

	"kitsune/internal/db"
)

// Service – сервис, который можно пустить через VPN при раздельной маршрутизации.
type Service struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Default bool   `json:"default"`
	rules   []Rule
}

func geosite(name string) Rule { return Rule{Type: "GEOSITE", Value: name, Action: "PROXY"} }
func geoip(name string) Rule   { return Rule{Type: "GEOIP", Value: name, Action: "PROXY"} }

// Services – набор как в 3X-UI KIT: наборы правил Mihomo (geosite/geoip).
var Services = []Service{
	{ID: "youtube", Label: "YouTube", Default: true, rules: []Rule{geosite("youtube")}},
	{ID: "telegram", Label: "Telegram", Default: true, rules: []Rule{geosite("telegram"), geoip("telegram")}},
	{ID: "meta", Label: "Instagram, Facebook, WhatsApp", Default: true, rules: []Rule{geosite("meta"), geoip("facebook")}},
	{ID: "twitter", Label: "X (Twitter)", Default: true, rules: []Rule{geosite("twitter"), geoip("twitter")}},
	{ID: "discord", Label: "Discord", Default: true, rules: []Rule{geosite("discord")}},
	{ID: "ai", Label: "ChatGPT, Claude и другие ИИ", Default: true, rules: []Rule{geosite("category-ai-!cn")}},
	{ID: "tiktok", Label: "TikTok", rules: []Rule{geosite("tiktok")}},
	{ID: "spotify", Label: "Spotify", rules: []Rule{geosite("spotify")}},
	{ID: "netflix", Label: "Netflix", rules: []Rule{geosite("netflix"), geoip("netflix")}},
	{ID: "github", Label: "GitHub", rules: []Rule{geosite("github")}},
	{ID: "twitch", Label: "Twitch", rules: []Rule{geosite("twitch")}},
}

// ClientRouting – настройки раздельной маршрутизации клиентов (хранятся в БД, ключ client_routing).
type ClientRouting struct {
	Mode     string   `json:"mode"`      // all | services | local-direct | custom
	Services []string `json:"services"`  // для режима services: идентификаторы сервисов
	Custom   string   `json:"custom"`    // свои правила, по одному в строке: ТИП,значение,действие
	BlockAds bool     `json:"block_ads"` // блокировать рекламу
	DoH      string   `json:"doh"`
	RUApps   bool     `json:"ru_apps"`   // местные приложения (по имени пакета) идут мимо туннеля
	LocalDNS string   `json:"local_dns"` // DNS для доменов, идущих напрямую (по умолчанию Яндекс DNS)
}

// DefaultLocalDNS – резолвер для прямых доменов: доступен и в сетях с ограничениями, в отличие от зарубежных DoH.
const DefaultLocalDNS = "77.88.8.8"

// RUAppPackages – имена Android-пакетов популярных местных приложений (правила PROCESS-NAME / package_name).
var RUAppPackages = []string{
	"com.vkontakte.android", "ru.ok.android", "ru.yandex.searchplugin", "ru.yandex.yandexmaps", "ru.yandex.taxi",
	"ru.sberbankmobile", "com.idamob.tinkoff.android", "ru.ozon.app.android", "com.wildberries.ru", "com.avito.android", "ru.rostel",
}

func DefaultClientRouting() ClientRouting {
	var ids []string
	for _, s := range Services {
		if s.Default {
			ids = append(ids, s.ID)
		}
	}
	return ClientRouting{Mode: "all", Services: ids}
}

func LoadClientRouting() ClientRouting {
	cr := DefaultClientRouting()
	if raw := db.GetSetting("client_routing", ""); strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &cr)
	}
	return cr
}

func SaveClientRouting(cr ClientRouting) error {
	b, err := json.Marshal(cr)
	if err != nil {
		return err
	}
	return db.SetSetting("client_routing", string(b))
}

// ParseCustom разбирает свои правила: «DOMAIN-SUFFIX,example.com,DIRECT». Некорректные строки пропускаются.
func ParseCustom(text string) []Rule {
	var out []Rule
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, ",")
		if len(p) < 2 {
			continue
		}
		t := strings.ToUpper(strings.TrimSpace(p[0]))
		switch t {
		case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "GEOSITE", "GEOIP":
		default:
			continue
		}
		act := "PROXY"
		if len(p) > 2 {
			act = strings.ToUpper(strings.TrimSpace(p[2]))
		}
		if act != "PROXY" && act != "DIRECT" && act != "REJECT" {
			act = "PROXY"
		}
		out = append(out, Rule{Type: t, Value: strings.TrimSpace(p[1]), Action: act})
	}
	return out
}

// Compile превращает настройки в правила подписки.
func (c ClientRouting) Compile() Routing {
	rt := Routing{DoH: c.DoH, RUApps: c.RUApps, LocalDNS: c.LocalDNS}
	if rt.LocalDNS == "" {
		rt.LocalDNS = DefaultLocalDNS
	}
	var rules []Rule
	if c.BlockAds {
		rules = append(rules, Rule{Type: "GEOSITE", Value: "category-ads-all", Action: "REJECT"})
	}
	rules = append(rules, ParseCustom(c.Custom)...)
	switch c.Mode {
	case "services":
		enabled := map[string]bool{}
		for _, id := range c.Services {
			enabled[id] = true
		}
		for _, s := range Services {
			if enabled[s.ID] {
				rules = append(rules, s.rules...)
			}
		}
		rt.Enable, rt.Final = true, "DIRECT"
	case "local-direct", "ru-direct": // ru-direct – прежнее имя режима
		rules = append(rules,
			Rule{Type: "GEOSITE", Value: "category-ru", Action: "DIRECT"},
			Rule{Type: "GEOIP", Value: "RU", Action: "DIRECT"})
		rt.Enable, rt.Final = true, "PROXY"
	case "custom":
		rt.Enable, rt.Final = true, "PROXY"
	default: // all
		rt.Enable = len(rules) > 0
		rt.Final = "PROXY"
	}
	rt.Rules = rules
	return rt
}
