package proto

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Parsed – разобранная ссылка на чужой сервер.
type Parsed struct {
	Scheme   string // vless | vmess | trojan | ss | hysteria2
	Name     string
	Server   string
	Port     int
	Outbound M // исходящее подключение Xray
}

func decodeB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("не base64")
}

func qv(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func portOf(u *url.URL) (int, error) {
	p, err := strconv.Atoi(u.Port())
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("в ссылке нет корректного порта")
	}
	return p, nil
}

// streamFromQuery собирает streamSettings исходящего Xray по параметрам ссылки (общий формат vless/trojan).
func streamFromQuery(q url.Values, defaultHost string) (M, error) {
	network := qv(q, "type")
	if network == "" {
		network = "tcp"
	}
	security := qv(q, "security")
	if security == "" {
		security = "none"
	}
	st := M{"network": network}
	switch network {
	case "ws":
		w := M{"path": firstNonEmpty(qv(q, "path"), "/")}
		if h := qv(q, "host"); h != "" {
			w["host"] = h
		}
		st["wsSettings"] = w
	case "grpc":
		g := M{"serviceName": qv(q, "serviceName")}
		if qv(q, "mode") == "multi" {
			g["multiMode"] = true
		}
		if a := qv(q, "authority"); a != "" {
			g["authority"] = a
		}
		st["grpcSettings"] = g
	case "xhttp", "splithttp":
		st["network"] = "xhttp"
		x := M{"path": firstNonEmpty(qv(q, "path"), "/"), "mode": firstNonEmpty(qv(q, "mode"), "auto")}
		if h := qv(q, "host"); h != "" {
			x["host"] = h
		}
		st["xhttpSettings"] = x
	case "httpupgrade":
		h := M{"path": firstNonEmpty(qv(q, "path"), "/")}
		if v := qv(q, "host"); v != "" {
			h["host"] = v
		}
		st["httpupgradeSettings"] = h
	case "tcp", "raw":
		st["network"] = "tcp"
	default:
		return nil, fmt.Errorf("транспорт %q не поддерживается", network)
	}
	switch security {
	case "none", "":
		st["security"] = "none"
	case "tls":
		t := M{"serverName": firstNonEmpty(qv(q, "sni", "peer"), defaultHost), "fingerprint": firstNonEmpty(qv(q, "fp"), "chrome")}
		if a := qv(q, "alpn"); a != "" {
			t["alpn"] = strings.Split(a, ",")
		}
		if pin := qv(q, "pcs", "pinSHA256"); pin != "" {
			t["pinnedPeerCertSha256"] = strings.ToLower(strings.ReplaceAll(pin, ":", ""))
		} else if qv(q, "allowInsecure", "insecure") == "1" || qv(q, "allowInsecure", "insecure") == "true" {
			t["allowInsecure"] = true
		}
		st["security"] = "tls"
		st["tlsSettings"] = t
	case "reality":
		if st["network"] == "ws" {
			return nil, errors.New("REALITY не работает с WebSocket")
		}
		st["security"] = "reality"
		st["realitySettings"] = M{"serverName": qv(q, "sni"), "fingerprint": firstNonEmpty(qv(q, "fp"), "chrome"), "password": qv(q, "pbk"),
			"shortId": qv(q, "sid"), "spiderX": firstNonEmpty(qv(q, "spx"), "/")}
	default:
		return nil, fmt.Errorf("защита %q не поддерживается", security)
	}
	return st, nil
}

// ParseLink разбирает ссылку vless://, vmess://, trojan://, ss://, hysteria2:// в исходящее подключение Xray.
func ParseLink(link string) (*Parsed, error) {
	link = strings.TrimSpace(link)
	scheme, _, ok := strings.Cut(link, "://")
	if !ok {
		return nil, errors.New("это не ссылка на сервер")
	}
	scheme = strings.ToLower(scheme)
	if scheme == "hy2" {
		scheme = "hysteria2"
		link = "hysteria2://" + strings.SplitN(link, "://", 2)[1]
	}
	if scheme == "vmess" {
		return parseVmess(link)
	}
	if scheme == "ss" {
		return parseSS(link)
	}
	u, err := url.Parse(link)
	if err != nil || u.Hostname() == "" {
		return nil, errors.New("ссылка не разобрана")
	}
	port, err := portOf(u)
	if err != nil {
		return nil, err
	}
	name, _ := url.PathUnescape(u.Fragment)
	q := u.Query()
	p := &Parsed{Scheme: scheme, Name: name, Server: u.Hostname(), Port: port}
	switch scheme {
	case "vless":
		st, err := streamFromQuery(q, u.Hostname())
		if err != nil {
			return nil, err
		}
		user := M{"id": u.User.Username(), "encryption": firstNonEmpty(qv(q, "encryption"), "none")}
		if f := qv(q, "flow"); f != "" {
			user["flow"] = f
		}
		p.Outbound = M{"protocol": "vless", "settings": M{"vnext": []M{{"address": p.Server, "port": port, "users": []M{user}}}}, "streamSettings": st}
	case "trojan":
		// url.Parse уже раскодировал имя пользователя: второе раскодирование ломает пароли с «%».
		// Пароль с незакодированным «:» (trojan://a:b@host) приходит как логин и пароль – склеиваем обратно.
		pw := u.User.Username()
		if rest, ok := u.User.Password(); ok {
			pw += ":" + rest
		}
		if qv(q, "security") == "" {
			q.Set("security", "tls")
		}
		st, err := streamFromQuery(q, u.Hostname())
		if err != nil {
			return nil, err
		}
		p.Outbound = M{"protocol": "trojan", "settings": M{"servers": []M{{"address": p.Server, "port": port, "password": pw}}}, "streamSettings": st}
	case "hysteria2":
		auth, _ := url.PathUnescape(u.User.String())
		t := M{"serverName": firstNonEmpty(qv(q, "sni"), u.Hostname()), "alpn": []string{"h3"}}
		if pin := qv(q, "pinSHA256"); pin != "" {
			t["pinnedPeerCertSha256"] = strings.ToLower(strings.ReplaceAll(pin, ":", ""))
		} else if qv(q, "insecure") == "1" {
			t["allowInsecure"] = true
		}
		st := M{"network": "hysteria", "security": "tls", "tlsSettings": t, "hysteriaSettings": M{"version": 2, "auth": auth}}
		if qv(q, "obfs") == "salamander" {
			st["finalmask"] = M{"udp": []M{{"type": "salamander", "settings": M{"password": qv(q, "obfs-password")}}}}
		}
		p.Outbound = M{"protocol": "hysteria", "settings": M{"version": 2, "address": p.Server, "port": port}, "streamSettings": st}
	default:
		return nil, fmt.Errorf("протокол %q не поддерживается (vless, vmess, trojan, ss, hysteria2)", scheme)
	}
	return p, nil
}

func parseVmess(link string) (*Parsed, error) {
	raw, err := decodeB64(strings.TrimPrefix(link, "vmess://"))
	if err != nil {
		return nil, errors.New("vmess-ссылка не разобрана")
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, errors.New("vmess-ссылка не разобрана")
	}
	str := func(k string) string {
		switch t := v[k].(type) {
		case string:
			return t
		case float64:
			return strconv.FormatFloat(t, 'f', -1, 64)
		}
		return ""
	}
	port, err := strconv.Atoi(str("port"))
	if err != nil || str("add") == "" {
		return nil, errors.New("в vmess-ссылке нет адреса или порта")
	}
	q := url.Values{"type": {firstNonEmpty(str("net"), "tcp")}, "path": {str("path")}, "host": {str("host")}, "sni": {str("sni")}, "fp": {str("fp")}, "alpn": {str("alpn")}}
	if str("tls") == "tls" {
		q.Set("security", "tls")
		if b, _ := v["allowInsecure"].(bool); b {
			q.Set("allowInsecure", "1")
		}
	}
	st, err := streamFromQuery(q, str("add"))
	if err != nil {
		return nil, err
	}
	return &Parsed{Scheme: "vmess", Name: str("ps"), Server: str("add"), Port: port, Outbound: M{"protocol": "vmess",
		"settings":       M{"vnext": []M{{"address": str("add"), "port": port, "users": []M{{"id": str("id"), "security": firstNonEmpty(str("scy"), "auto")}}}}},
		"streamSettings": st}}, nil
}

func parseSS(link string) (*Parsed, error) {
	rest := strings.TrimPrefix(link, "ss://")
	name := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		name, _ = url.PathUnescape(rest[i+1:])
		rest = rest[:i]
	}
	if i := strings.Index(rest, "?"); i >= 0 { // плагины не поддерживаются
		rest = rest[:i]
	}
	var userinfo, hostport string
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		userinfo, hostport = rest[:at], rest[at+1:]
		if dec, err := decodeB64(userinfo); err == nil && strings.Contains(string(dec), ":") {
			userinfo = string(dec)
		} else if un, err := url.PathUnescape(userinfo); err == nil {
			userinfo = un
		}
	} else {
		dec, err := decodeB64(rest)
		if err != nil {
			return nil, errors.New("ss-ссылка не разобрана")
		}
		s := string(dec)
		at := strings.LastIndex(s, "@")
		if at < 0 {
			return nil, errors.New("ss-ссылка не разобрана")
		}
		userinfo, hostport = s[:at], s[at+1:]
	}
	method, password, ok := strings.Cut(userinfo, ":")
	if !ok || method == "" {
		return nil, errors.New("в ss-ссылке нет шифра и пароля")
	}
	host, ps, found := strings.Cut(hostport, ":")
	if i := strings.LastIndex(hostport, ":"); i >= 0 && strings.Contains(hostport, "[") {
		host, ps, found = strings.Trim(hostport[:i], "[]"), hostport[i+1:], true
	}
	port, err := strconv.Atoi(strings.TrimSuffix(ps, "/"))
	if !found || err != nil || host == "" {
		return nil, errors.New("в ss-ссылке нет адреса или порта")
	}
	return &Parsed{Scheme: "ss", Name: name, Server: host, Port: port, Outbound: M{"protocol": "shadowsocks",
		"settings": M{"servers": []M{{"address": host, "port": port, "method": method, "password": password}}}}}, nil
}
