// Package sub собирает подписки для приложений: список ссылок, профиль Clash/Mihomo и конфиг sing-box.
package sub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"kitsune/internal/bridge"
	"kitsune/internal/db"
	"kitsune/internal/pro"
	"kitsune/internal/proto"
)

var (
	clashUA   = regexp.MustCompile(`(?i)(clash|mihomo|flclash|stash|nyanpasu|meta|verge)`)
	singboxUA = regexp.MustCompile(`(?i)(sing-?box|sfa|sfi|sfm|sft)`)
	// Hiddify 4.x в строке приложения называет себя и Clash, но Clash-YAML читает неверно («Unable to determine config format»):
	// ему отдаём обычный список ссылок, который он разбирает без проблем.
	hiddifyUA = regexp.MustCompile(`(?i)hiddify`)
	incyUA    = regexp.MustCompile(`(?i)incy`)
	// Приложения на sing-box, которые просят Clash, но не умеют часть протоколов, тут не перечисляем:
	// формат выбирается по заголовку User-Agent или параметру ?format=.
)

const (
	FormatRaw     = "raw"
	FormatClash   = "clash"
	FormatSingbox = "singbox"
)

// DetectFormat выбирает формат подписки по параметру format или User-Agent.
func DetectFormat(format, userAgent string) string {
	switch strings.ToLower(format) {
	case "clash", "mihomo", "yaml":
		return FormatClash
	case "singbox", "sing-box", "json":
		return FormatSingbox
	case "xray", "xray-json", "v2ray-json":
		return FormatXray
	case "raw", "links", "base64", "v2ray":
		return FormatRaw
	}
	switch {
	case hiddifyUA.MatchString(userAgent):
		return FormatRaw
	case incyUA.MatchString(userAgent):
		return FormatXray
	case singboxUA.MatchString(userAgent):
		return FormatSingbox
	case clashUA.MatchString(userAgent):
		return FormatClash
	}
	return FormatRaw
}

// Rule – одно правило раздельной маршрутизации клиента.
type Rule struct {
	Type   string `json:"type"` // DOMAIN | DOMAIN-SUFFIX | DOMAIN-KEYWORD | IP-CIDR | GEOSITE | GEOIP
	Value  string `json:"value"`
	Action string `json:"action"` // PROXY | DIRECT | REJECT
}

// Routing – раздельная маршрутизация, которая приезжает вместе с подпиской.
type Routing struct {
	Enable bool   `json:"enable"`
	Final  string `json:"final"` // PROXY | DIRECT: что делать со всем остальным
	Rules  []Rule `json:"rules"`
	DoH    string `json:"doh"`

	RUApps   bool   `json:"ru_apps"`
	LocalDNS string `json:"local_dns"`
}

// Profiles – подключения пользователя во всех включённых шлюзах.
func Profiles(u db.User, env proto.Env) []*proto.Profile {
	inbounds, _ := db.GetInbounds()
	gm := db.GroupMap()
	var out []*proto.Profile
	for _, ib := range inbounds {
		if !ib.Enable || !db.Allowed(gm, u, ib.ID) {
			continue
		}
		p, err := proto.NewProfile(ib, u, env)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	if db.GetSetting("sub_udp_first", "0") == "1" {
		// UDP-подключения впереди: у сетей, где TCP-передача останавливается, клиент сначала пробует их
		isUDP := func(p *proto.Profile) bool { i, ok := proto.Get(p.Kind); return ok && i.Net == "udp" }
		sort.SliceStable(out, func(i, j int) bool { return isUDP(out[i]) && !isUDP(out[j]) })
	}
	return pro.ExpandRelays(bridge.Expand(out))
}

// Raw – ссылки по одной на строку, закодированные в base64 (формат v2rayN, Hiddify, Happ и других).
func Raw(profiles []*proto.Profile) string {
	var sb strings.Builder
	for _, p := range profiles {
		if l := p.URI(); l != "" {
			sb.WriteString(l)
			sb.WriteString("\n")
		}
	}
	for _, l := range pro.ExternalLinks() {
		sb.WriteString(l + "\n")
	}
	return base64.StdEncoding.EncodeToString([]byte(sb.String()))
}

// Links – ссылки без кодирования (для показа в панели).
func Links(profiles []*proto.Profile) []string {
	var out []string
	for _, p := range profiles {
		if l := p.URI(); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func action(a string) string {
	switch strings.ToUpper(a) {
	case "DIRECT":
		return "DIRECT"
	case "REJECT":
		return "REJECT"
	}
	return "Kitsune"
}

// Clash собирает полный профиль Mihomo/Clash Meta.
func Clash(profiles []*proto.Profile, rt Routing) ([]byte, error) {
	var proxies []proto.M
	var names []string
	for _, p := range profiles {
		if m := p.Clash(); m != nil {
			proxies = append(proxies, m)
			names = append(names, p.Name)
		}
	}
	if len(proxies) == 0 {
		return nil, fmt.Errorf("нет подключений, поддерживаемых Clash")
	}
	doh := rt.DoH
	if doh == "" {
		doh = "https://1.1.1.1/dns-query"
	}
	var rules []string
	rules = append(rules, "GEOIP,private,DIRECT,no-resolve")
	if rt.RUApps {
		for _, pkg := range RUAppPackages {
			rules = append(rules, "PROCESS-NAME,"+pkg+",DIRECT")
		}
	}
	if rt.Enable {
		for _, r := range rt.Rules {
			t := strings.ToUpper(r.Type)
			v := strings.TrimSpace(r.Value)
			if v == "" {
				continue
			}
			line := fmt.Sprintf("%s,%s,%s", t, v, action(r.Action))
			if t == "IP-CIDR" || t == "IP-CIDR6" || t == "GEOIP" {
				line += ",no-resolve"
			}
			rules = append(rules, line)
		}
		if strings.EqualFold(rt.Final, "DIRECT") {
			rules = append(rules, "MATCH,DIRECT")
		} else {
			rules = append(rules, "MATCH,Kitsune")
		}
	} else {
		rules = append(rules, "MATCH,Kitsune")
	}
	groupNames := append([]string{"Авто", "Резерв"}, names...)
	dns := proto.M{"enable": true, "ipv6": false, "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
		"nameserver": []string{doh}, "default-nameserver": []string{"1.1.1.1", "8.8.8.8"}}
	if rt.Enable {
		// Прямые домены резолвим локальным DNS: зарубежные DoH в сетях с ограничениями часто недоступны.
		local := rt.LocalDNS
		if local == "" {
			local = DefaultLocalDNS
		}
		policy := proto.M{}
		var geos []string
		for _, r := range rt.Rules {
			if !strings.EqualFold(r.Action, "DIRECT") {
				continue
			}
			v := strings.TrimSpace(r.Value)
			switch strings.ToUpper(r.Type) {
			case "GEOSITE":
				geos = append(geos, "geosite:"+v)
			case "DOMAIN-SUFFIX":
				policy["+."+v] = []string{local}
			case "DOMAIN":
				policy[v] = []string{local}
			}
		}
		if len(geos) > 0 {
			policy[strings.Join(geos, ",")] = []string{local}
		}
		if len(policy) > 0 {
			dns["nameserver-policy"] = policy
			dns["default-nameserver"] = []string{local, "1.1.1.1"}
		}
	}
	cfg := proto.M{
		"mixed-port": 7890, "allow-lan": false, "mode": "rule", "log-level": "info", "ipv6": false,
		"unified-delay": true, "geodata-mode": true,
		"dns":     dns,
		"proxies": proxies,
		"proxy-groups": []proto.M{
			{"name": "Kitsune", "type": "select", "proxies": groupNames},
			{"name": "Авто", "type": "url-test", "proxies": names, "url": "https://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50},
			{"name": "Резерв", "type": "fallback", "proxies": names, "url": "https://www.gstatic.com/generate_204", "interval": 300},
		},
		"rules": rules,
	}
	return yaml.Marshal(cfg)
}

// Singbox собирает клиентский конфиг sing-box (правила – простые домены и подсети).
func Singbox(profiles []*proto.Profile, rt Routing) ([]byte, error) {
	var outs []proto.M
	var tags []string
	for _, p := range profiles {
		if m := p.SingBox(); m != nil {
			outs = append(outs, m)
			tags = append(tags, p.Name)
		}
	}
	if len(outs) == 0 {
		return nil, fmt.Errorf("нет подключений, поддерживаемых sing-box")
	}
	outbounds := []proto.M{
		{"type": "selector", "tag": "Kitsune", "outbounds": append([]string{"Авто"}, tags...), "default": "Авто"},
		{"type": "urltest", "tag": "Авто", "outbounds": tags, "url": "https://www.gstatic.com/generate_204", "interval": "5m", "tolerance": 50},
	}
	outbounds = append(outbounds, outs...)
	outbounds = append(outbounds, proto.M{"type": "direct", "tag": "direct"})

	rules := []proto.M{{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"}, {"ip_is_private": true, "outbound": "direct"}}
	if rt.RUApps {
		rules = append(rules, proto.M{"package_name": RUAppPackages, "outbound": "direct"})
	}
	var localSuffix, localDomain []string
	if rt.Enable {
		for _, r := range rt.Rules {
			v := strings.TrimSpace(r.Value)
			if v == "" {
				continue
			}
			out := "Kitsune"
			if strings.EqualFold(r.Action, "DIRECT") {
				out = "direct"
			}
			rule := proto.M{"outbound": out}
			if strings.EqualFold(r.Action, "REJECT") {
				rule = proto.M{"action": "reject"}
			}
			switch strings.ToUpper(r.Type) {
			case "DOMAIN":
				rule["domain"] = []string{v}
				if out == "direct" {
					localDomain = append(localDomain, v)
				}
			case "DOMAIN-SUFFIX":
				rule["domain_suffix"] = []string{v}
				if out == "direct" {
					localSuffix = append(localSuffix, v)
				}
			case "DOMAIN-KEYWORD":
				rule["domain_keyword"] = []string{v}
			case "IP-CIDR", "IP-CIDR6":
				rule["ip_cidr"] = []string{v}
			default:
				continue // GEOSITE/GEOIP в sing-box требуют наборов правил – в этом конфиге не используются
			}
			rules = append(rules, rule)
		}
	}
	final := "Kitsune"
	if rt.Enable && strings.EqualFold(rt.Final, "DIRECT") {
		final = "direct"
	}
	local := rt.LocalDNS
	if local == "" {
		local = DefaultLocalDNS
	}
	dnsServers := []proto.M{
		{"tag": "remote", "type": "https", "server": "1.1.1.1", "detour": "Kitsune"},
		{"tag": "local", "type": "local"},
		{"tag": "ru", "type": "udp", "server": local},
	}
	dns := proto.M{"servers": dnsServers, "final": "remote"}
	var dnsRules []proto.M
	if len(localSuffix) > 0 {
		dnsRules = append(dnsRules, proto.M{"domain_suffix": localSuffix, "server": "ru"})
	}
	if len(localDomain) > 0 {
		dnsRules = append(dnsRules, proto.M{"domain": localDomain, "server": "ru"})
	}
	if len(dnsRules) > 0 {
		dns["rules"] = dnsRules
	}
	cfg := proto.M{
		"log":       proto.M{"level": "warn"},
		"dns":       dns,
		"inbounds":  []proto.M{{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}},
		"outbounds": outbounds,
		"route":     proto.M{"rules": rules, "final": final, "auto_detect_interface": true, "default_domain_resolver": "local"},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// UserInfoHeader – Subscription-Userinfo. Нулевой срок («бессрочно») не передаём: приложения рисуют 1970 год.
func UserInfoHeader(u db.User) string {
	parts := []string{fmt.Sprintf("upload=0; download=%d", u.UsedTraffic)}
	if u.TrafficLimit > 0 {
		parts = append(parts, fmt.Sprintf("total=%d", u.TrafficLimit))
	}
	if u.ExpiryTime > 0 {
		parts = append(parts, fmt.Sprintf("expire=%d", u.ExpiryTime/1000))
	}
	return strings.Join(parts, "; ")
}

// ForClient убирает подключения, которые этот клиент заведомо не умеет. Karing (iOS) показывает узел NaiveProxy,
// но подключиться через него не может – красный узел ему не отдаём.
func ForClient(profiles []*proto.Profile, userAgent string) []*proto.Profile {
	if !strings.Contains(strings.ToLower(userAgent), "karing") {
		return profiles
	}
	out := make([]*proto.Profile, 0, len(profiles))
	for _, p := range profiles {
		if p.Kind != proto.Naive {
			out = append(out, p)
		}
	}
	return out
}
