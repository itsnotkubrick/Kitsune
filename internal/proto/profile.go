package proto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"kitsune/internal/cert"
	"kitsune/internal/db"
)

// Profile – подключение глазами клиента: адрес, порт и параметры пользователя.
// Из него строятся ссылки, профили Clash, исходящие sing-box и Xray (для проверки с самого сервера).
type Profile struct {
	Kind     Kind
	Name     string // имя в приложении
	Host     string
	Port     int
	S        Settings
	U        db.User
	SNI      string   // serverName для TLS/REALITY
	Insecure bool     // самоподписанный сертификат – клиенту нужно закрепление или отключение проверки
	Pin      string   // sha256 сертификата (hex), если самоподписанный
	AWG      *AWGPeer // ключи и адрес пользователя в туннеле (AmneziaWG)
}

// NewProfile готовит профиль пользователя в подключении. Адрес берётся из внешних настроек подключения или из env.
func NewProfile(in db.Inbound, u db.User, env Env) (*Profile, error) {
	k := Kind(in.Kind)
	if _, ok := Get(k); !ok {
		return nil, fmt.Errorf("неизвестный тип подключения %q", in.Kind)
	}
	s := ParseSettings(in.Settings)
	port := in.Port
	if Routed(in, env) {
		port = 443
	}
	p := &Profile{Kind: k, Name: in.Tag, Host: firstNonEmpty(s.ExternalHost, env.Host), Port: intOf(s.ExternalPort, port), S: s, U: u}
	switch k {
	case AWG, AWG3:
		if peer, ok := ParseAWGPeer(db.ClientData(u.ID, in.ID)); ok {
			p.AWG = &peer
		}
	case VlessReality, VlessXHTTP:
		p.SNI = s.SNI
	case VlessWS, VmessWS, TrojanGRPC, Hysteria2, TUIC, Naive, Masque:
		p.SNI = s.serverName(env)
		// NaiveProxy проверяет сертификат по адресу, к которому подключается, а не по отдельному SNI:
		// с доверенным сертификатом на домен в подписке должен быть домен, а не IP сервера.
		if k == Naive && (s.CertMode == "custom" || s.CertMode == "acme") && s.ExternalHost == "" && net.ParseIP(p.SNI) == nil && p.SNI != "" {
			p.Host = p.SNI
		}
		if s.CertMode != "custom" && s.CertMode != "acme" { // доверенный сертификат: закрепление не нужно
			p.Insecure = true
			if crt, _, _, err := s.TLSFiles(env); err == nil {
				p.Pin = cert.Fingerprint(crt)
			}
		}
	}
	return p, nil
}

func qs(v url.Values) string {
	for _, k := range []string{"sni", "host"} { // пустое имя в ссылку не пишем
		if v.Has(k) && v.Get(k) == "" {
			v.Del(k)
		}
	}
	return strings.ReplaceAll(v.Encode(), "+", "%20")
}

func frag(name string) string { return url.PathEscape(name) }

// userEsc экранирует имя или пароль для части «логин:пароль@» в ссылке: PathEscape оставляет «@» и «:», а они ломают разбор.
func userEsc(s string) string {
	return strings.NewReplacer("@", "%40", ":", "%3A").Replace(url.PathEscape(s))
}

func b64url(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// URI – ссылка для импорта в приложение. Для типов без стандартной ссылки возвращает пустую строку.
func (p *Profile) URI() string {
	s, u := p.S, p.U
	hostport := fmt.Sprintf("%s:%d", hostLiteral(p.Host), p.Port)
	switch p.Kind {
	case VlessReality:
		q := url.Values{"encryption": {"none"}, "security": {"reality"}, "sni": {p.SNI}, "fp": {firstNonEmpty(s.Fingerprint, "chrome")},
			"pbk": {s.PublicKey}, "sid": {firstSID(s)}, "spx": {firstNonEmpty(s.SpiderX, "/")}, "type": {"tcp"}, "headerType": {"none"}}
		if f := s.flowFor(u); f != "" {
			q.Set("flow", f)
		}
		return fmt.Sprintf("vless://%s@%s?%s#%s", u.UUID, hostport, qs(q), frag(p.Name))
	case VlessXHTTP:
		q := url.Values{"encryption": {"none"}, "security": {"reality"}, "sni": {p.SNI}, "fp": {firstNonEmpty(s.Fingerprint, "chrome")},
			"pbk": {s.PublicKey}, "sid": {firstSID(s)}, "spx": {firstNonEmpty(s.SpiderX, "/")}, "type": {"xhttp"},
			"path": {s.Path}, "mode": {firstNonEmpty(s.Mode, "auto")}}
		if s.Host != "" {
			q.Set("host", s.Host)
		}
		return fmt.Sprintf("vless://%s@%s?%s#%s", u.UUID, hostport, qs(q), frag(p.Name))
	case VlessWS:
		q := p.tlsQuery("http/1.1")
		q.Set("encryption", "none")
		q.Set("type", "ws")
		q.Set("path", s.Path)
		q.Set("host", firstNonEmpty(s.Host, p.SNI))
		return fmt.Sprintf("vless://%s@%s?%s#%s", u.UUID, hostport, qs(q), frag(p.Name))
	case TrojanGRPC:
		q := p.tlsQuery("h2")
		q.Set("type", "grpc")
		q.Set("serviceName", s.ServiceName)
		q.Set("mode", map[bool]string{true: "multi", false: "gun"}[boolOf(s.MultiMode, false)])
		if s.Authority != "" {
			q.Set("authority", s.Authority)
		}
		return fmt.Sprintf("trojan://%s@%s?%s#%s", userEsc(u.Password), hostport, qs(q), frag(p.Name))
	case VmessWS:
		obj := map[string]any{"v": "2", "ps": p.Name, "add": p.Host, "port": strconv.Itoa(p.Port), "id": u.UUID, "aid": "0", "scy": "auto",
			"net": "ws", "type": "none", "host": firstNonEmpty(s.Host, p.SNI), "path": s.Path, "tls": "tls", "sni": p.SNI,
			"alpn": "http/1.1", "fp": firstNonEmpty(s.Fingerprint, "chrome")}
		if p.Insecure {
			obj["allowInsecure"] = true
		}
		raw, _ := json.Marshal(obj)
		return "vmess://" + base64.StdEncoding.EncodeToString(raw)
	case SS2022:
		cred := s.Method + ":" + s.ServerKey + ":" + p.userSSKey()
		return fmt.Sprintf("ss://%s@%s#%s", b64url(cred), hostport, frag(p.Name))
	case Hysteria2:
		q := url.Values{"sni": {p.SNI}}
		if p.Insecure {
			q.Set("insecure", "1")
			if p.Pin != "" {
				q.Set("pinSHA256", p.Pin)
			}
		}
		if s.ObfsPassword != "" {
			q.Set("obfs", "salamander")
			q.Set("obfs-password", s.ObfsPassword)
		}
		return fmt.Sprintf("hysteria2://%s@%s/?%s#%s", userEsc(u.Password), hostport, qs(q), frag(p.Name))
	case TUIC:
		q := url.Values{"congestion_control": {firstNonEmpty(s.Congestion, "bbr")}, "udp_relay_mode": {firstNonEmpty(s.UDPRelayMode, "native")},
			"alpn": {"h3"}, "sni": {p.SNI}}
		if p.Insecure {
			q.Set("allow_insecure", "1")
		}
		return fmt.Sprintf("tuic://%s:%s@%s?%s#%s", u.UUID, userEsc(u.Password), hostport, qs(q), frag(p.Name))
	case Naive:
		return fmt.Sprintf("naive+https://%s:%s@%s#%s", userEsc(u.Name), userEsc(u.Password), hostport, frag(p.Name))
	case Mieru:
		q := url.Values{}
		q.Set("profile", p.Name)
		q.Set("mtu", firstNonEmpty(s.MTU, "1400"))
		q.Set("multiplexing", firstNonEmpty(s.Multiplexing, "MULTIPLEXING_LOW"))
		q.Set("protocol", firstNonEmpty(s.Transport, "TCP"))
		if pr := strings.TrimSpace(s.PortRange); pr != "" {
			q.Set("port", pr)
		} else {
			q.Set("port", strconv.Itoa(p.Port))
		}
		return fmt.Sprintf("mierus://%s:%s@%s?%s", userEsc(u.Name), userEsc(u.Password), hostLiteral(p.Host), qs(q))
	case MTProto:
		secret := s.Secret
		if s.Engine == "telemt" {
			us := MTProtoUserSecret(db.MTProtoSalt(), u.UUID)
			if us == "" { // соли нет – личный секрет не выдаём
				return ""
			}
			secret = MTProtoLinkSecret(us, s.FakeTLS)
		}
		q := url.Values{"server": {p.Host}, "port": {strconv.Itoa(p.Port)}, "secret": {secret}}
		return "tg://proxy?" + qs(q)
	case AWG, AWG3:
		return p.AmneziaURI()
	}
	return ""
}

func (p *Profile) tlsQuery(alpn string) url.Values {
	q := url.Values{"security": {"tls"}, "sni": {p.SNI}, "fp": {firstNonEmpty(p.S.Fingerprint, "chrome")}, "alpn": {alpn}}
	if p.Insecure {
		q.Set("allowInsecure", "1")
		if p.Pin != "" {
			q.Set("pcs", p.Pin)
		}
	}
	return q
}

func (p *Profile) userSSKey() string {
	if SSKeySize(p.S.Method) == 16 {
		return p.U.SSKey16()
	}
	return p.U.SSKey32()
}

func firstSID(s Settings) string {
	if l := s.ShortIDList(); len(l) > 0 {
		return l[0]
	}
	return ""
}

// hostLiteral оборачивает IPv6 в скобки.
func hostLiteral(h string) string {
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		return "[" + h + "]"
	}
	return h
}
