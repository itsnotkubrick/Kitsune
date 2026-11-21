// Package bridge – каскад: дополнительная точка входа на сервере в другой сети (например, в другой стране), который
// пересылает соединения клиентов на основной сервер. Клиент подключается к адресу моста с теми же ключами и настройками,
// узел только пересылает трафик на уровне TCP/UDP и ничего не расшифровывает. Узлу не нужна ни панель, ни ядра.
//
// Мост работает, только если его адрес доступен из сети клиента. Это проверяется измерениями, а не предполагается.
package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"kitsune/internal/db"
	"kitsune/internal/proto"
)

const settingKey = "bridges"

var subscriptionSnapshot atomic.Pointer[[]Node]

// FreezeSubscriptions keeps old bridge profiles visible until core application commits.
// The API serializes writers; readers never see a half-applied SNI configuration.
func FreezeSubscriptions(nodes []Node) func() {
	subscriptionSnapshot.Store(&nodes)
	return func() { subscriptionSnapshot.Store(nil) }
}

// Node – узел-мост. Host – IPv4 или доменное имя узла. Enabled – добавлять ли его в подписки.
type Node struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Host    string `json:"host"`
	Enabled bool   `json:"enabled"`
	// SNI – необязательное имя сайта для REALITY-копий через этот узел (иначе берётся имя подключения). Сервер принимает его
	// наравне с основным, поэтому имя должно обслуживаться тем же сайтом-маскировкой (например, соседний поддомен).
	SNI string `json:"sni,omitempty"`
	// Only – теги подключений, которые идут через этот узел (пусто – все пересылаемые). Остальные в копиях через узел не участвуют,
	// и скрипт узла пересылает только их порты.
	Only []string `json:"only,omitempty"`
	// SelectionMode is additive: missing preserves legacy empty Only = all.
	SelectionMode string `json:"selection_mode,omitempty"`
	// AutoHide – убирать копии этого узла из подписки, пока он не отвечает по TCP (проверка с сервера, три неудачи подряд).
	AutoHide bool `json:"auto_hide,omitempty"`
}

var (
	idRe   = regexp.MustCompile(`^[a-z0-9]{4,16}$`)
	hostRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

// List возвращает сохранённые узлы.
func List() []Node {
	var out []Node
	_ = json.Unmarshal([]byte(db.GetSetting(settingKey, "[]")), &out)
	return out
}

// Validate проверяет список узлов и приводит поля в порядок.
func Validate(list []Node) ([]Node, error) {
	if len(list) > 10 {
		return nil, fmt.Errorf("не больше 10 узлов")
	}
	seen := map[string]bool{}
	out := make([]Node, 0, len(list))
	for _, n := range list {
		n.Name = strings.TrimSpace(n.Name)
		n.Host = strings.ToLower(strings.TrimSpace(n.Host))
		if n.Name == "" || len([]rune(n.Name)) > 30 {
			return nil, fmt.Errorf("имя узла: от 1 до 30 символов")
		}
		if strings.ContainsAny(n.Name, "\n\r\t#%") {
			return nil, fmt.Errorf("в имени узла «%s» есть недопустимые символы", n.Name)
		}
		if err := CheckHost(n.Host); err != nil {
			return nil, fmt.Errorf("узел «%s»: %w", n.Name, err)
		}
		if n.SelectionMode != "" && n.SelectionMode != "all" && n.SelectionMode != "selected" && n.SelectionMode != "none" {
			return nil, fmt.Errorf("неверный режим выбора подключений")
		}
		n.Only = cleanTags(n.Only)
		if n.SelectionMode == "selected" && len(n.Only) == 0 {
			return nil, fmt.Errorf("выберите хотя бы одно подключение")
		}
		if n.SelectionMode == "all" || n.SelectionMode == "none" {
			n.Only = nil
		}
		n.SNI = strings.ToLower(strings.TrimSpace(n.SNI))
		if n.SNI != "" && (net.ParseIP(n.SNI) != nil || !hostRe.MatchString(n.SNI) || len(n.SNI) > 253) {
			return nil, fmt.Errorf("узел «%s»: SNI должно быть доменным именем сайта, например www.example.com", n.Name)
		}
		if n.ID == "" || !idRe.MatchString(n.ID) || seen[n.ID] {
			n.ID = db.RandomAlnum(8)
			n.ID = strings.ToLower(n.ID)
		}
		seen[n.ID] = true
		out = append(out, n)
	}
	return out, nil
}

// CheckHost: адрес моста – публичный IPv4 или доменное имя.
func CheckHost(h string) error {
	if ip := net.ParseIP(h); ip != nil {
		v4 := ip.To4()
		if v4 == nil {
			return fmt.Errorf("пока поддерживается только IPv4")
		}
		if !publicIPv4(ip) {
			return fmt.Errorf("нужен публичный адрес, а не %s", h)
		}
		return nil
	}
	if len(h) > 253 || !hostRe.MatchString(h) {
		return fmt.Errorf("укажите IPv4-адрес или доменное имя")
	}
	return nil
}

// Save сохраняет узлы.
func Save(list []Node) ([]Node, error) {
	v, err := Validate(list)
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(v)
	return v, db.SetSetting(settingKey, string(b))
}

// Relayable – можно ли переслать подключение этого типа простой пересылкой портов. UDP-протоколы (Hysteria2, TUIC)
// тоже пересылаются, но их качество через пересылку нужно проверять отдельно; AmneziaWG, MTProto и Mieru в мост не идут.
func Relayable(k proto.Kind) bool {
	switch k {
	case proto.VlessReality, proto.VlessXHTTP, proto.VlessWS, proto.TrojanGRPC, proto.VmessWS, proto.SS2022, proto.Hysteria2, proto.TUIC:
		return true
	}
	return false
}

// Expand добавляет к профилям копии с адресом каждого включённого узла: те же ключи, порт и имя сайта, другой адрес.
func Expand(in []*proto.Profile) []*proto.Profile {
	nodes := List()
	if frozen := subscriptionSnapshot.Load(); frozen != nil {
		nodes = *frozen
	}
	if len(nodes) == 0 {
		return in
	}
	out := append([]*proto.Profile(nil), in...)
	for _, n := range nodes {
		if !n.Enabled || CheckHost(n.Host) != nil {
			continue
		}

		for _, p := range in {
			if !Relayable(p.Kind) || !n.Takes(p.Name) {
				continue
			}
			info, _ := proto.Get(p.Kind)
			// TCP reachability never proves failure of UDP (or the UDP half of SS2022).
			if n.AutoHide && info.Net == "tcp" && ProfileDown(n, p.Port) {
				continue
			}
			c := *p
			// Имя для проверки TLS не должно смениться вместе с адресом: клиент идёт на узел, а сертификат и имя остаются прежними.
			if c.SNI == "" {
				c.SNI = p.Host
			}
			c.Host = n.Host
			if n.SNI != "" && (p.Kind == proto.VlessReality || p.Kind == proto.VlessXHTTP) {
				c.SNI = n.SNI
			}
			c.Name = p.Name + " · " + n.Name
			out = append(out, &c)
		}
	}
	return out
}

// Forward – одно правило пересылки: порт узла -> порт и адрес основного сервера.
type Forward struct {
	Proto string // tcp или udp
	Port  int
}

// Forwards – порты включённых подключений, которые нужно переслать (без повторов, по порядку).
func Forwards(inbounds []db.Inbound, env proto.Env) []Forward {
	seen := map[Forward]bool{}
	var out []Forward
	for _, ib := range inbounds {
		if !ib.Enable || !Relayable(proto.Kind(ib.Kind)) {
			continue
		}
		info, ok := proto.Get(proto.Kind(ib.Kind))
		if !ok {
			continue
		}
		port := ib.Port
		if proto.Routed(ib, env) {
			port = 443
		}
		f := Forward{Proto: info.Net, Port: port}
		if f.Proto == "" {
			f.Proto = "tcp"
		}
		fs := []Forward{f}
		if f.Proto == "both" {
			fs = []Forward{{Proto: "tcp", Port: port}, {Proto: "udp", Port: port}}
		}
		for _, f := range fs {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}

func portList(fw []Forward) string {
	parts := make([]string, 0, len(fw))
	for _, f := range fw {
		parts = append(parts, fmt.Sprintf("%d/%s", f.Port, f.Proto))
	}
	return strings.Join(parts, ", ")
}

func init() {
	// REALITY-сервер должен принимать имена, под которыми клиенты ходят через узлы
	proto.ExtraRealitySNIs = ExtraSNIs
	proto.InboundRealitySNIs = func(tag string) []string {
		var out []string
		for _, n := range List() {
			if n.Enabled && n.SNI != "" && n.Takes(tag) {
				out = append(out, n.SNI)
			}
		}
		return out
	}
}

// ExtraSNIs – имена сайтов включённых узлов (без повторов): их добавляют в serverNames REALITY.
func ExtraSNIs() []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range List() {
		if n.Enabled && n.SNI != "" && !seen[n.SNI] {
			seen[n.SNI] = true
			out = append(out, n.SNI)
		}
	}
	return out
}

// Takes: идёт ли подключение с этим тегом через узел.
func (n Node) Takes(tag string) bool {
	if n.SelectionMode == "none" {
		return false
	}
	if n.SelectionMode == "all" {
		return true
	}
	if len(n.Only) == 0 {
		return true
	}
	for _, t := range n.Only {
		if t == tag {
			return true
		}
	}
	return false
}

// Select оставляет подключения, выбранные для узла (пустой список – все).
func Select(inbounds []db.Inbound, only []string) []db.Inbound {
	if len(only) == 0 {
		return inbounds
	}
	n := Node{Only: only}
	var out []db.Inbound
	for _, ib := range inbounds {
		if n.Takes(ib.Tag) {
			out = append(out, ib)
		}
	}
	return out
}

func cleanTags(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" || len([]rune(t)) > 60 || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
		if len(out) >= 50 {
			break
		}
	}
	return out
}

// ResolveHost возвращает публичный IPv4 узла для проверки: имя разрешается здесь, на внутренние адреса не ходим.
func ResolveHost(host string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return ResolveHostContext(ctx, host)
}

func ResolveHostContext(ctx context.Context, host string) (string, error) {
	if err := CheckHost(host); err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.To4().String(), nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("имя не разрешается в адрес")
	}
	for _, ip := range ips {
		if !publicIPv4(ip) {
			return "", fmt.Errorf("имя указывает на непубличный адрес")
		}
	}
	return ips[0].To4().String(), nil
}

// Documentation prefixes are allowed for offline configurations/tests; reject routable
// internal and special-use destinations consistently for literals and DNS answers.
func publicIPv4(ip net.IP) bool {
	v := ip.To4()
	if v == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	return v[0] != 0 && v[0] < 224 && !(v[0] == 100 && v[1] >= 64 && v[1] <= 127) && !(v[0] == 198 && (v[1] == 18 || v[1] == 19)) && !(v[0] == 192 && v[1] == 0 && v[2] == 0)
}

func (n Node) Select(in []db.Inbound) []db.Inbound {
	var out []db.Inbound
	for _, ib := range in {
		if n.Takes(ib.Tag) {
			out = append(out, ib)
		}
	}
	return out
}

// ValidatePorts prevents publishing bridge profiles that disagree with the NAT script.
func ValidatePorts(in []db.Inbound, env proto.Env) error {
	for _, ib := range in {
		if !ib.Enable || !Relayable(proto.Kind(ib.Kind)) {
			continue
		}
		port := ib.Port
		if proto.Routed(ib, env) {
			port = 443
		}
		s := proto.ParseSettings(ib.Settings)
		if s.ExternalPort != "" && s.ExternalPort != fmt.Sprint(port) {
			return fmt.Errorf("подключение %s: внешний порт отличается от порта моста", ib.Tag)
		}
	}
	return nil
}
