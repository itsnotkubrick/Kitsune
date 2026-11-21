package sub

import (
	"encoding/json"
	"fmt"

	"kitsune/internal/proto"
)

// FormatXray – подписка массивом полных конфигов Xray: первый элемент «Авто» с проверкой доступности и балансировщиком,
// дальше по одному серверу на подключение. Клиент сам проверяет подключения из сети человека и уходит с заблокированного.
const FormatXray = "xray"

// xrayClientKinds – типы, которые клиенты на Xray разбирают без сюрпризов: один неизвестный тип ломает весь конфиг.
var xrayClientKinds = map[proto.Kind]bool{
	proto.VlessReality: true, proto.VlessXHTTP: true, proto.VlessWS: true,
	proto.VmessWS: true, proto.TrojanGRPC: true, proto.SS2022: true,
}

const xrayProbeURL = "https://www.gstatic.com/generate_204"

type xrayOut struct {
	tag string
	out proto.M
}

func xrayOutbounds(profiles []*proto.Profile) []xrayOut {
	var res []xrayOut
	for _, p := range profiles {
		if !xrayClientKinds[p.Kind] {
			continue
		}
		o := p.XrayOutbound()
		if o == nil {
			continue
		}
		tag := fmt.Sprintf("srv-%d", len(res)+1)
		o["tag"] = tag
		res = append(res, xrayOut{tag: tag, out: o})
	}
	return res
}

func xrayBase(remark string, outs []proto.M, rules []proto.M, extra proto.M) proto.M {
	outs = append(outs, proto.M{"tag": "direct", "protocol": "freedom"}, proto.M{"tag": "block", "protocol": "blackhole"})
	cfg := proto.M{
		"remarks": remark,
		"log":     proto.M{"loglevel": "warning"},
		"dns": proto.M{
			"servers":       []any{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"},
			"queryStrategy": "UseIPv4",
		},
		"inbounds": []proto.M{
			{"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 10808,
				"settings": proto.M{"auth": "noauth", "udp": true},
				"sniffing": proto.M{"enabled": true, "destOverride": []string{"http", "tls", "quic"}}},
			{"tag": "http-in", "protocol": "http", "listen": "127.0.0.1", "port": 10809},
		},
		"outbounds": outs,
		"stats":     proto.M{},
	}
	routing := proto.M{"domainStrategy": "IPIfNonMatch", "rules": rules}
	for k, v := range extra {
		if k == "routing" {
			for rk, rv := range v.(proto.M) {
				routing[rk] = rv
			}
			continue
		}
		cfg[k] = v
	}
	cfg["routing"] = routing
	return cfg
}

// XrayJSON собирает подписку для клиентов на Xray. Если подходящих подключений нет – ошибка, чтобы отдать обычный список.
func XrayJSON(profiles []*proto.Profile) ([]byte, error) {
	list := xrayOutbounds(profiles)
	if len(list) == 0 {
		return nil, fmt.Errorf("нет подключений, которые поймёт клиент Xray")
	}
	// адреса DNS идут напрямую: иначе проверка ждёт DNS, DNS ждёт балансировщик, а он ждёт проверку
	direct := proto.M{"type": "field", "ip": []string{"1.1.1.1", "8.8.8.8"}, "outboundTag": "direct"}
	private := proto.M{"type": "field", "ip": []string{"geoip:private"}, "outboundTag": "direct"}
	configs := []proto.M{}
	if len(list) > 1 {
		outs := make([]proto.M, 0, len(list))
		tags := make([]string, 0, len(list))
		for _, x := range list {
			o := proto.M{}
			for k, v := range x.out {
				o[k] = v
			}
			outs = append(outs, o)
			tags = append(tags, x.tag)
		}
		configs = append(configs, xrayBase("Kitsune: Авто", outs,
			[]proto.M{direct, private, {"type": "field", "network": "tcp,udp", "balancerTag": "auto"}},
			proto.M{
				"routing": proto.M{"balancers": []proto.M{{"tag": "auto", "selector": tags, "strategy": proto.M{"type": "leastPing"}}}},
				"burstObservatory": proto.M{"subjectSelector": tags, "pingConfig": proto.M{
					"destination": xrayProbeURL, "connectivity": xrayProbeURL, "interval": "60s", "sampling": 2, "timeout": "5s"}},
			}))
	}
	configs = append(configs, xrayNamed(profiles)...)
	return json.MarshalIndent(configs, "", "  ")
}

// xrayNamed – по конфигу на каждое подключение с понятным названием.
func xrayNamed(profiles []*proto.Profile) []proto.M {
	var res []proto.M
	for _, p := range profiles {
		if !xrayClientKinds[p.Kind] {
			continue
		}
		o := p.XrayOutbound()
		if o == nil {
			continue
		}
		o["tag"] = "proxy"
		res = append(res, xrayBase("Kitsune: "+p.Name, []proto.M{o},
			[]proto.M{{"type": "field", "ip": []string{"geoip:private"}, "outboundTag": "direct"}, {"type": "field", "network": "tcp,udp", "outboundTag": "proxy"}}, nil))
	}
	return res
}
