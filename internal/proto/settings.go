package proto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Settings – параметры подключения, хранятся в inbounds.settings как JSON. Поля плоские: каждый тип
// использует свою часть. Числа и флаги приходят из формы строками, поэтому разбор терпимый (см. UnmarshalJSON).
type Settings struct {
	Listen       string `json:"listen,omitempty"`
	Sniffing     string `json:"sniffing,omitempty"`   // "true"/"false"; пусто = включён
	RouteOnly    string `json:"route_only,omitempty"` // "true"/"false"
	XrayPatch    string `json:"xray_patch,omitempty"` // JSON, который вливается в подключение Xray (merge)
	ExternalHost string `json:"external_host,omitempty"`
	ExternalPort string `json:"external_port,omitempty"`

	// REALITY
	SNI         string `json:"sni,omitempty"`
	Target      string `json:"target,omitempty"`
	PrivateKey  string `json:"private_key,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
	ShortIDs    string `json:"short_ids,omitempty"`
	SpiderX     string `json:"spider_x,omitempty"`
	Xver        string `json:"xver,omitempty"`
	MaxTimeDiff string `json:"max_time_diff,omitempty"`
	AcceptProxy string `json:"accept_proxy,omitempty"`
	Flow        string `json:"flow,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	OldSNIs     string `json:"old_snis,omitempty"` // прежние сайты маскировки «имя:срок-unix,…»: ещё неделю принимаются сервером

	// Транспорты
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	Mode        string `json:"mode,omitempty"`
	NoSSE       string `json:"no_sse_header,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	Authority   string `json:"authority,omitempty"`
	MultiMode   string `json:"multi_mode,omitempty"`

	// TLS
	CertMode   string `json:"cert_mode,omitempty"`
	CertFile   string `json:"cert_file,omitempty"`
	KeyFile    string `json:"key_file,omitempty"`
	MinVersion string `json:"min_version,omitempty"`

	// Shadowsocks 2022
	Method    string `json:"method,omitempty"`
	ServerKey string `json:"server_key,omitempty"`
	Network   string `json:"network,omitempty"`

	// Hysteria2
	Masquerade     string `json:"masquerade,omitempty"`
	ObfsPassword   string `json:"obfs_password,omitempty"`
	UpMbps         string `json:"up_mbps,omitempty"`
	DownMbps       string `json:"down_mbps,omitempty"`
	UDPIdleTimeout string `json:"udp_idle_timeout,omitempty"`

	// TUIC / Naive
	Congestion     string `json:"congestion,omitempty"`
	UDPRelayMode   string `json:"udp_relay_mode,omitempty"`
	ZeroRTT        string `json:"zero_rtt,omitempty"`
	Heartbeat      string `json:"heartbeat,omitempty"`
	AuthTimeout    string `json:"auth_timeout,omitempty"`
	QUICCongestion string `json:"quic_congestion,omitempty"`
	NaiveNetwork   string `json:"naive_network,omitempty"`

	// Mieru
	Transport    string `json:"transport,omitempty"`
	MTU          string `json:"mtu,omitempty"`
	PortRange    string `json:"port_range,omitempty"`
	Multiplexing string `json:"multiplexing,omitempty"`

	// MTProto
	FakeTLS        string `json:"fake_tls,omitempty"`
	Secret         string `json:"secret,omitempty"`
	MTGConcurrency string `json:"mtg_concurrency,omitempty"`
	Engine         string `json:"engine,omitempty"` // mtg (один общий секрет) | telemt (секрет у каждого пользователя)
	PreferIP       string `json:"prefer_ip,omitempty"`

	// AmneziaWG
	Subnet    string `json:"subnet,omitempty"`
	DNS       string `json:"dns,omitempty"`
	Keepalive string `json:"keepalive,omitempty"`
	Jc        string `json:"jc,omitempty"`
	Jmin      string `json:"jmin,omitempty"`
	Jmax      string `json:"jmax,omitempty"`
	S1        string `json:"s1,omitempty"`
	S2        string `json:"s2,omitempty"`
	S3        string `json:"s3,omitempty"`
	S4        string `json:"s4,omitempty"`
	H1        string `json:"h1,omitempty"`
	H2        string `json:"h2,omitempty"`
	H3        string `json:"h3,omitempty"`
	H4        string `json:"h4,omitempty"`
	I1        string `json:"i1,omitempty"`
	I2        string `json:"i2,omitempty"`
	I3        string `json:"i3,omitempty"`
	I4        string `json:"i4,omitempty"`
	I5        string `json:"i5,omitempty"`
	HeaderKey string `json:"header_key,omitempty"` // ключ защиты заголовков AmneziaWG 3.1 (hex, 32 байта)

	// Тайминги клиента AmneziaWG 3.1 (число или диапазон «мин-макс»); сервер их не использует, они уходят только в клиентский .conf.
	RekeyAfterTime         string `json:"rekey_after_time,omitempty"`
	RekeyTimeout           string `json:"rekey_timeout,omitempty"`
	RejectAfterTime        string `json:"reject_after_time,omitempty"`
	KeepaliveTimeout       string `json:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts   string `json:"max_handshake_attempts,omitempty"`
	ContentPaddingAddition string `json:"content_padding_addition,omitempty"`
}

// UnmarshalJSON принимает значения любого скалярного типа и приводит их к строкам:
// форма отдаёт всё строками, а ручной JSON может содержать числа и true/false.
func (s *Settings) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	norm := map[string]string{}
	for k, v := range raw {
		switch t := v.(type) {
		case string:
			norm[k] = t
		case bool:
			norm[k] = strconv.FormatBool(t)
		case float64:
			norm[k] = strconv.FormatFloat(t, 'f', -1, 64)
		case nil:
		default:
			b, _ := json.Marshal(t)
			norm[k] = string(b)
		}
	}
	type plain Settings
	b, _ := json.Marshal(norm)
	return json.Unmarshal(b, (*plain)(s))
}

// ParseSettings читает settings из БД; пустая строка – пустые настройки.
func ParseSettings(raw string) Settings {
	var s Settings
	if strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &s)
	}
	return s
}

func (s Settings) JSON() string {
	b, _ := json.Marshal(s)
	return string(b)
}

// Helpers: разбор строковых значений.
func boolOf(v string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	}
	return def
}

// IsRange проверяет значение вида «25» или «25-35»: число или диапазон из двух чисел.
func IsRange(v string) bool {
	a, b, isRange := strings.Cut(strings.TrimSpace(v), "-")
	for _, p := range []string{a, b} {
		if p == "" && !isRange {
			continue
		}
		if n, err := strconv.Atoi(p); err != nil || n < 0 {
			return false
		}
	}
	return a != ""
}

// firstInt берёт первое число из значения «25» или «25-35».
func firstInt(v string, def int) int {
	a, _, _ := strings.Cut(strings.TrimSpace(v), "-")
	return intOf(a, def)
}

func intOf(v string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
		return n
	}
	return def
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// Sniff – включён ли sniffing (по умолчанию да).
func (s Settings) Sniff() bool { return boolOf(s.Sniffing, true) }

func (s Settings) ShortIDList() []string {
	var out []string
	for _, p := range strings.Split(s.ShortIDs, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Список надёжных сайтов маскировки для REALITY (TLS 1.3, HTTP/2, не за CDN-блокировками).
var DefaultSNIs = []string{"dl.google.com", "www.amazon.com", "www.samsung.com", "www.yahoo.com", "addons.mozilla.org",
	"www.oracle.com", "www.nvidia.com", "www.intel.com"}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randPath(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	var sb strings.Builder
	for i := 0; i < n; i++ {
		v, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		sb.WriteByte(alphabet[v.Int64()])
	}
	return sb.String()
}

func randBase64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// RealityKeys создаёт пару x25519 в формате REALITY (base64url без дополнения).
func RealityKeys() (priv, pub string, err error) {
	var k [32]byte
	if _, err = rand.Read(k[:]); err != nil {
		return
	}
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	var p [32]byte
	curve25519.ScalarBaseMult(&p, &k)
	return base64.RawURLEncoding.EncodeToString(k[:]), base64.RawURLEncoding.EncodeToString(p[:]), nil
}

// SSKeySize – размер ключа в байтах для метода Shadowsocks 2022.
func SSKeySize(method string) int {
	if strings.Contains(method, "aes-128") {
		return 16
	}
	return 32
}

// MTProtoSecret формирует секрет FakeTLS: ee + 16 случайных байт + домен (всё в hex).
func MTProtoSecret(domain string) string {
	return "ee" + randHex(16) + hex.EncodeToString([]byte(domain))
}

// Fill заполняет недостающие значения тип-зависимыми умолчаниями и генерирует ключи и секреты.
// Уже заданные значения не трогает – можно вызывать при каждом сохранении.
func (s *Settings) Fill(kind Kind) error {
	def := func(p *string, v string) {
		if strings.TrimSpace(*p) == "" {
			*p = v
		}
	}
	switch kind {
	case VlessReality, VlessXHTTP:
		if kind == VlessXHTTP {
			def(&s.SNI, DefaultSNIs[1]) // свой сайт: в режиме «всё на 443» имена подключений различаются
		} else {
			def(&s.SNI, DefaultSNIs[0])
		}
		def(&s.Fingerprint, "chrome")
		def(&s.SpiderX, "/")
		if kind == VlessXHTTP {
			def(&s.Path, "/"+randPath(10))
			def(&s.Mode, "auto")
		}
		if s.PrivateKey == "" || s.PublicKey == "" {
			priv, pub, err := RealityKeys()
			if err != nil {
				return err
			}
			s.PrivateKey, s.PublicKey = priv, pub
		}
		if s.ShortIDs == "" {
			s.ShortIDs = randHex(8)
		}
		def(&s.Xver, "0")
	case VlessWS, VmessWS:
		def(&s.Path, "/"+randPath(10))
		def(&s.CertMode, "self")
		def(&s.Fingerprint, "chrome")
	case TrojanGRPC:
		def(&s.ServiceName, randPath(8))
		def(&s.CertMode, "self")
		def(&s.Fingerprint, "chrome")
	case SS2022:
		def(&s.Method, "2022-blake3-aes-128-gcm")
		def(&s.Network, "tcp,udp")
		if s.ServerKey == "" {
			s.ServerKey = randBase64(SSKeySize(s.Method))
		}
	case Hysteria2:
		def(&s.CertMode, "self")
		def(&s.Fingerprint, "chrome")
		def(&s.UDPIdleTimeout, "60")
	case TUIC:
		def(&s.CertMode, "self")
		def(&s.Congestion, "bbr")
		def(&s.UDPRelayMode, "native")
		def(&s.Heartbeat, "10s")
		def(&s.AuthTimeout, "3s")
	case Naive:
		def(&s.CertMode, "self")
		def(&s.QUICCongestion, "bbr")
	case Masque:
		def(&s.CertMode, "self")
		def(&s.Subnet, "10.77.0.0/24")
		def(&s.MTU, "1280")
	case Mieru:
		def(&s.Transport, "TCP")
		def(&s.MTU, "1400")
		def(&s.Multiplexing, "MULTIPLEXING_LOW")
	case MTProto:
		def(&s.Engine, "mtg")
		def(&s.FakeTLS, "www.cloudflare.com")
		def(&s.MTGConcurrency, "8192")
		def(&s.PreferIP, "prefer-ipv4")
		if s.Secret == "" {
			s.Secret = MTProtoSecret(s.FakeTLS)
		}
	case AWG, AWG3:
		return s.fillAWG(kind)
	default:
		return fmt.Errorf("неизвестный тип подключения %q", kind)
	}
	return nil
}

// wgKeys – пара x25519 в формате WireGuard (обычный base64 с дополнением).
func wgKeys() (priv, pub string, err error) {
	var k [32]byte
	if _, err = rand.Read(k[:]); err != nil {
		return
	}
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	var p [32]byte
	curve25519.ScalarBaseMult(&p, &k)
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(p[:]), nil
}

// WithOldSNI запоминает прежний сайт маскировки: сервер принимает его ещё grace, пока клиенты обновят подписку.
func (s *Settings) WithOldSNI(old string, until int64) {
	if strings.TrimSpace(old) == "" || old == s.SNI {
		return
	}
	var parts []string
	now := time.Now().Unix()
	for _, p := range strings.Split(s.OldSNIs, ",") {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			if t, err := strconv.ParseInt(kv[1], 10, 64); err == nil && t > now && kv[0] != old {
				parts = append(parts, p)
			}
		}
	}
	parts = append(parts, fmt.Sprintf("%s:%d", old, until))
	s.OldSNIs = strings.Join(parts, ",")
}

// ActiveSNIs – текущий сайт маскировки и ещё действующие прежние.
func (s Settings) ActiveSNIs() []string {
	out := []string{s.SNI}
	now := time.Now().Unix()
	for _, p := range strings.Split(s.OldSNIs, ",") {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			if t, err := strconv.ParseInt(kv[1], 10, 64); err == nil && t > now && kv[0] != s.SNI {
				out = append(out, kv[0])
			}
		}
	}
	return out
}

// MTProtoUserSecret – личный секрет пользователя для движка telemt: 32 hex-символа. Зависит от UUID и соли установки
// (db.MTProtoSalt), поэтому постоянен для пользователя на этой установке и не выводится из одного UUID.
// Без соли секрет не выдаётся (пустая строка): иначе он выводился бы из одного UUID.
func MTProtoUserSecret(salt, uuid string) string {
	if salt == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte("kitsune-mtproto|" + uuid))
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

// MTProtoLinkSecret – секрет для ссылки tg://: ee + секрет + домен маскировки в hex.
func MTProtoLinkSecret(secret32, domain string) string {
	return "ee" + secret32 + hex.EncodeToString([]byte(domain))
}
