package proto

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"kitsune/internal/acme"
	"kitsune/internal/cert"
	"kitsune/internal/db"
	"kitsune/internal/stub"
)

// Env – окружение, в котором строятся конфиги и ссылки.
type Env struct {
	Host   string // публичный адрес сервера (IP или домен)
	StubID string // страница-заглушка для ответа постороннему (Hysteria2)
	// MasqURL – локальный адрес «обычного сайта» (internal/site): Hysteria проксирует на него ответы постороннему, и они совпадают
	// с ответами сайта на своём домене. Пусто – слушатель не запущен, тогда встроенная страница (type string).
	MasqURL string
	Single  bool // режим «всё на 443»: TCP-подключения слушают локально, наружу их выводит SNI-маршрутизатор
}

// InnerPort – локальный порт подключения в режиме «всё на 443».
func InnerPort(id int) int { return 10400 + id }

// RoutableNames – имена (SNI), по которым маршрутизатор на 443 направляет трафик в подключение.
// Пустой список – подключение в этом режиме остаётся на своём порту.
func RoutableNames(in db.Inbound) []string {
	s := ParseSettings(in.Settings)
	switch Kind(in.Kind) {
	case VlessReality, VlessXHTTP:
		return s.ActiveSNIs()
	case VlessWS, VmessWS, TrojanGRPC:
		// TLS-протоколы различаются только по имени: нужен собственный домен (клиент по IP SNI не шлёт)
		if n := strings.TrimSpace(s.SNI); n != "" && net.ParseIP(n) == nil {
			return []string{n}
		}
	case MTProto:
		if n := strings.TrimSpace(s.FakeTLS); n != "" {
			return []string{n}
		}
	}
	return nil
}

// Routed – подключение вынесено на 443 (в режиме single).
func Routed(in db.Inbound, env Env) bool { return env.Single && len(RoutableNames(in)) > 0 }

// Cred – пользователь в конкретном подключении.
type Cred struct {
	Email string
	User  db.User
}

type M = map[string]any

// flowFor – flow VLESS для пользователя: Vision включается и в подключении, и у пользователя.
func (s Settings) flowFor(u db.User) string {
	f := s.Flow
	if f == "" {
		f = "xtls-rprx-vision"
	}
	if f == "none" || !u.Vision {
		return ""
	}
	return f
}

// TLSFiles возвращает пути сертификата и ключа; самоподписанный выпускается при необходимости.
func (s Settings) TLSFiles(env Env) (certFile, keyFile string, self bool, err error) {
	if s.CertMode == "custom" && s.CertFile != "" && s.KeyFile != "" {
		return s.CertFile, s.KeyFile, false, nil
	}
	if s.CertMode == "acme" {
		crt, key, _, err := acme.Files(s.SNI)
		return crt, key, false, err
	}
	host := firstNonEmpty(s.SNI, env.Host)
	p, err := cert.EnsureSelfSigned(host)
	if err != nil {
		return "", "", true, err
	}
	return p.CertFile, p.KeyFile, true, nil
}

// serverName – SNI, который клиенты указывают для TLS-подключений. IP-адрес в SNI не пишем
// (стандарт его не допускает, а такая метка отличает подключение): без домена имя в профиле пустое,
// клиент сам подключается по адресу сервера.
func (s Settings) serverName(env Env) string {
	n := strings.TrimSpace(firstNonEmpty(s.SNI, env.Host))
	if net.ParseIP(strings.Trim(n, "[]")) != nil {
		return ""
	}
	return n
}

func (s Settings) tlsSettings(env Env, alpn []string) (M, error) {
	crt, key, _, err := s.TLSFiles(env)
	if err != nil {
		return nil, err
	}
	t := M{
		"alpn":         alpn,
		"certificates": []M{{"certificateFile": crt, "keyFile": key}},
	}
	if s.SNI != "" {
		t["serverName"] = s.SNI
	}
	if s.MinVersion != "" {
		t["minVersion"] = s.MinVersion
	}
	return t, nil
}

func (s Settings) realitySettings(tags ...string) M {
	names := withExtraSNIs(s.ActiveSNIs())
	if len(tags) > 0 {
		names = withInboundSNIs(s.ActiveSNIs(), tags[0])
	}
	target := firstNonEmpty(s.Target, s.SNI+":443")
	r := M{
		"show":        false,
		"target":      target,
		"xver":        intOf(s.Xver, 0),
		"serverNames": names,
		"privateKey":  s.PrivateKey,
		"shortIds":    s.ShortIDList(),
	}
	if n := intOf(s.MaxTimeDiff, 0); n > 0 {
		r["maxTimeDiff"] = n
	}
	return r
}

func sockopt(s Settings) M {
	if boolOf(s.AcceptProxy, false) {
		return M{"acceptProxyProtocol": true}
	}
	return nil
}

// BuildXray собирает подключение для config.json Xray. Для типов других ядер возвращает nil, nil.
func BuildXray(in db.Inbound, creds []Cred, env Env) (M, error) {
	info, ok := Get(Kind(in.Kind))
	if !ok || info.Core != CoreXray {
		return nil, nil
	}
	s := ParseSettings(in.Settings)

	ib := M{"tag": in.Tag, "port": in.Port}
	if s.Listen != "" {
		ib["listen"] = s.Listen
	}
	routed := Routed(in, env) && Kind(in.Kind) != MTProto
	if routed {
		ib["listen"], ib["port"] = "127.0.0.1", InnerPort(in.ID)
	}
	if s.Sniff() {
		ib["sniffing"] = M{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": boolOf(s.RouteOnly, false)}
	}

	var stream M
	switch Kind(in.Kind) {
	case VlessReality:
		var cl []M
		for _, c := range creds {
			m := M{"id": c.User.UUID, "email": c.Email}
			if f := s.flowFor(c.User); f != "" {
				m["flow"] = f
			}
			cl = append(cl, m)
		}
		ib["protocol"] = "vless"
		ib["settings"] = M{"clients": nonNil(cl), "decryption": "none"}
		stream = M{"network": "tcp", "security": "reality", "realitySettings": s.realitySettings(in.Tag)}

	case VlessXHTTP:
		var cl []M
		for _, c := range creds {
			cl = append(cl, M{"id": c.User.UUID, "email": c.Email})
		}
		ib["protocol"] = "vless"
		ib["settings"] = M{"clients": nonNil(cl), "decryption": "none"}
		x := M{"path": s.Path, "mode": firstNonEmpty(s.Mode, "auto")}
		if s.Host != "" {
			x["host"] = s.Host
		}
		if boolOf(s.NoSSE, false) {
			x["noSSEHeader"] = true
		}
		stream = M{"network": "xhttp", "security": "reality", "xhttpSettings": x, "realitySettings": s.realitySettings(in.Tag)}

	case VlessWS:
		var cl []M
		for _, c := range creds {
			cl = append(cl, M{"id": c.User.UUID, "email": c.Email})
		}
		tls, err := s.tlsSettings(env, []string{"http/1.1"})
		if err != nil {
			return nil, err
		}
		ib["protocol"] = "vless"
		ib["settings"] = M{"clients": nonNil(cl), "decryption": "none"}
		stream = M{"network": "ws", "security": "tls", "wsSettings": wsSettings(s), "tlsSettings": tls}

	case VmessWS:
		var cl []M
		for _, c := range creds {
			cl = append(cl, M{"id": c.User.UUID, "email": c.Email})
		}
		tls, err := s.tlsSettings(env, []string{"http/1.1"})
		if err != nil {
			return nil, err
		}
		ib["protocol"] = "vmess"
		ib["settings"] = M{"clients": nonNil(cl)}
		stream = M{"network": "ws", "security": "tls", "wsSettings": wsSettings(s), "tlsSettings": tls}

	case TrojanGRPC:
		var cl []M
		for _, c := range creds {
			cl = append(cl, M{"password": c.User.Password, "email": c.Email})
		}
		tls, err := s.tlsSettings(env, []string{"h2"})
		if err != nil {
			return nil, err
		}
		g := M{"serviceName": s.ServiceName}
		if s.Authority != "" {
			g["authority"] = s.Authority
		}
		if boolOf(s.MultiMode, false) {
			g["multiMode"] = true
		}
		ib["protocol"] = "trojan"
		ib["settings"] = M{"clients": nonNil(cl)}
		stream = M{"network": "grpc", "security": "tls", "grpcSettings": g, "tlsSettings": tls}

	case SS2022:
		var cl []M
		for _, c := range creds {
			key := c.User.SSKey32()
			if SSKeySize(s.Method) == 16 {
				key = c.User.SSKey16()
			}
			cl = append(cl, M{"password": key, "email": c.Email})
		}
		ib["protocol"] = "shadowsocks"
		ib["settings"] = M{"method": s.Method, "password": s.ServerKey, "network": firstNonEmpty(s.Network, "tcp,udp"), "clients": nonNil(cl)}

	case Hysteria2:
		var us []M
		for _, c := range creds {
			us = append(us, M{"auth": c.User.Password, "email": c.Email})
		}
		tls, err := s.tlsSettings(env, []string{"h3"})
		if err != nil {
			return nil, err
		}
		h := M{"version": 2, "udpIdleTimeout": intOf(s.UDPIdleTimeout, 60)}
		if m := s.hysteriaMasquerade(env); m != nil {
			h["masquerade"] = m
		}
		ib["protocol"] = "hysteria"
		ib["settings"] = M{"version": 2, "users": nonNil(us)}
		stream = M{"network": "hysteria", "security": "tls", "tlsSettings": tls, "hysteriaSettings": h}
		fm := M{}
		if s.ObfsPassword != "" {
			fm["udp"] = []M{{"type": "salamander", "settings": M{"password": s.ObfsPassword}}}
		}
		qp := M{}
		if n := intOf(s.UpMbps, 0); n > 0 {
			qp["brutalUp"] = fmt.Sprintf("%d mbps", n)
		}
		if n := intOf(s.DownMbps, 0); n > 0 {
			qp["brutalDown"] = fmt.Sprintf("%d mbps", n)
		}
		if len(qp) > 0 {
			fm["quicParams"] = qp
		}
		if len(fm) > 0 {
			stream["finalmask"] = fm
		}
	}

	if so := sockopt(s); so != nil && stream != nil {
		stream["sockopt"] = so
	}
	if routed && stream != nil { // маршрутизатор передаёт настоящий адрес клиента заголовком PROXY protocol
		so, _ := stream["sockopt"].(M)
		if so == nil {
			so = M{}
		}
		so["acceptProxyProtocol"] = true
		stream["sockopt"] = so
	}
	if stream != nil {
		ib["streamSettings"] = stream
	}
	if strings.TrimSpace(s.XrayPatch) != "" {
		var patch M
		if err := json.Unmarshal([]byte(s.XrayPatch), &patch); err != nil {
			return nil, fmt.Errorf("свой JSON подключения %s: %w", in.Tag, err)
		}
		mergeInto(ib, patch)
	}
	return ib, nil
}

func nonNil(v []M) []M {
	if v == nil {
		return []M{}
	}
	return v
}

func wsSettings(s Settings) M {
	w := M{"path": s.Path}
	if s.Host != "" {
		w["host"] = s.Host
	}
	return w
}

// masquerade: URL -> прокси на сайт, иначе HTML-страница, пусто -> стандартный 404.
// hysteriaMasquerade – что Hysteria2 отвечает постороннему по HTTP/3. Своё поле «Маскировка» (адрес или HTML) главнее; иначе
// проксирование на локальный «обычный сайт» панели (те же ответы, что у сайта на своём домене), а если его слушатель не
// запущен – встроенная страница заглушки.
func (s Settings) hysteriaMasquerade(env Env) M {
	if m := s.masquerade(); m != nil {
		return m
	}
	if env.MasqURL != "" {
		return M{"type": "proxy", "url": env.MasqURL, "rewriteHost": true}
	}
	if env.StubID != "" {
		return M{"type": "string", "content": stub.HTML(env.StubID), "statusCode": 200, "headers": M{"content-type": "text/html; charset=utf-8"}}
	}
	return nil
}

func (s Settings) masquerade() M {
	v := strings.TrimSpace(s.Masquerade)
	switch {
	case v == "":
		return nil
	case strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://"):
		return M{"type": "proxy", "url": v, "rewriteHost": true}
	default:
		return M{"type": "string", "content": v, "statusCode": 200, "headers": M{"content-type": "text/html; charset=utf-8"}}
	}
}

// mergeInto рекурсивно вливает patch в dst (объекты сливаются, остальное заменяется).
func mergeInto(dst, patch M) {
	for k, v := range patch {
		pm, pok := v.(map[string]any)
		dm, dok := dst[k].(M)
		if pok && dok {
			mergeInto(dm, pm)
			continue
		}
		dst[k] = v
	}
}

// ExtraRealitySNIs возвращает дополнительные имена сайтов, которые REALITY-сервер принимает (задаёт пакет bridge).
var ExtraRealitySNIs func() []string

func withExtraSNIs(base []string) []string {
	if ExtraRealitySNIs == nil {
		return base
	}
	seen := map[string]bool{}
	for _, b := range base {
		seen[b] = true
	}
	out := append([]string(nil), base...)
	for _, e := range ExtraRealitySNIs() {
		if e != "" && !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out
}

// InboundRealitySNIs scopes bridge names to the selected connection.
var InboundRealitySNIs func(string) []string

func withInboundSNIs(base []string, tag string) []string {
	if InboundRealitySNIs == nil {
		return withExtraSNIs(base)
	}
	seen := map[string]bool{}
	out := append([]string(nil), base...)
	for _, v := range base {
		seen[v] = true
	}
	for _, v := range InboundRealitySNIs(tag) {
		if v != "" && !seen[v] {
			out = append(out, v)
			seen[v] = true
		}
	}
	return out
}
