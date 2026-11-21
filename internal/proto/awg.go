package proto

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// fillAWG задаёт параметры обфускации AmneziaWG. Для 3.1 по рекомендации документации заголовки H1–H4 = 1, 2, 3, 4.
func (s *Settings) fillAWG(kind Kind) error {
	def := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	if kind == AWG3 {
		def(&s.Subnet, "10.8.2.0/24")
	} else {
		def(&s.Subnet, "10.8.1.0/24")
	}
	def(&s.DNS, "1.1.1.1")
	def(&s.MTU, "1280")
	def(&s.Keepalive, "25")
	def(&s.Jc, "4")
	def(&s.Jmin, "40")
	def(&s.Jmax, "70")
	def(&s.S1, "15")
	def(&s.S2, "68")
	def(&s.H1, "1")
	def(&s.H2, "2")
	def(&s.H3, "3")
	def(&s.H4, "4")
	if kind == AWG3 {
		def(&s.S3, "20")
		def(&s.S4, "20")
		// значения по умолчанию, как в клиентском конфиге приложения AmneziaVPN
		def(&s.RekeyAfterTime, "100-120")
		def(&s.RekeyTimeout, "3-8")
		def(&s.RejectAfterTime, "150-180")
		def(&s.KeepaliveTimeout, "7-13")
		def(&s.MaxHandshakeAttempts, "15-20")
		def(&s.ContentPaddingAddition, "10-100")
	}
	if s.PrivateKey == "" || s.PublicKey == "" {
		priv, pub, err := wgKeys()
		if err != nil {
			return err
		}
		s.PrivateKey, s.PublicKey = priv, pub
	}
	if kind == AWG3 && s.HeaderKey == "" {
		s.HeaderKey = randHex(32)
	}
	return nil
}

// ClientHeaderKey – ключ защиты заголовков в виде для клиентов: base64 (32 байта), как ключи WireGuard.
// В настройках и на сервере (UAPI) ключ хранится в hex; значение, уже заданное в base64, возвращается как есть.
func ClientHeaderKey(key string) string {
	key = strings.TrimSpace(key)
	if raw, err := hex.DecodeString(key); err == nil && len(raw) == 32 {
		return base64.StdEncoding.EncodeToString(raw)
	}
	return key
}

// NormalizeHeaderKey принимает ключ защиты заголовков в hex (64 символа) или base64 (44 символа, 32 байта)
// и возвращает hex – в таком виде он хранится и уходит серверу.
func NormalizeHeaderKey(key string) (string, error) {
	key = strings.TrimSpace(key)
	if raw, err := hex.DecodeString(key); err == nil && len(raw) == 32 {
		return strings.ToLower(key), nil
	}
	if raw, err := base64.StdEncoding.DecodeString(key); err == nil && len(raw) == 32 {
		return hex.EncodeToString(raw), nil
	}
	return "", fmt.Errorf("ключ защиты заголовков должен быть 32 байта: 64 символа hex или 44 символа base64")
}

// AWGPeer – ключи и адрес пользователя в туннеле AmneziaWG.
type AWGPeer struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	PSK        string `json:"psk"`
	IP         string `json:"ip"` // без маски, например 10.8.1.2
}

func ParseAWGPeer(raw string) (AWGPeer, bool) {
	var p AWGPeer
	if raw == "" || json.Unmarshal([]byte(raw), &p) != nil || p.PrivateKey == "" || p.IP == "" {
		return p, false
	}
	return p, true
}

func (p AWGPeer) JSON() string { b, _ := json.Marshal(p); return string(b) }

// NewAWGPeer создаёт ключи пира и берёт первый свободный адрес подсети (.1 – сервер).
func NewAWGPeer(subnet string, used []string) (AWGPeer, error) {
	ip, err := FreeIP(subnet, used)
	if err != nil {
		return AWGPeer{}, err
	}
	priv, pub, err := wgKeys()
	if err != nil {
		return AWGPeer{}, err
	}
	return AWGPeer{PrivateKey: priv, PublicKey: pub, PSK: randBase64(32), IP: ip}, nil
}

// ServerAddr – адрес сервера в туннеле с маской подсети (первый адрес подсети).
func ServerAddr(subnet string) (string, error) {
	ip, n, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", err
	}
	_ = ip
	base := n.IP.To4()
	if base == nil {
		return "", fmt.Errorf("поддерживаются только IPv4-подсети")
	}
	first := net.IPv4(base[0], base[1], base[2], base[3]+1)
	ones, _ := n.Mask.Size()
	return fmt.Sprintf("%s/%d", first, ones), nil
}

// FreeIP возвращает первый свободный адрес подсети, начиная с .2.
func FreeIP(subnet string, used []string) (string, error) {
	_, n, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", err
	}
	base := n.IP.To4()
	if base == nil {
		return "", fmt.Errorf("поддерживаются только IPv4-подсети")
	}
	taken := map[string]bool{}
	for _, u := range used {
		taken[u] = true
	}
	ones, bits := n.Mask.Size()
	size := 1 << uint(bits-ones)
	start := binary.BigEndian.Uint32(base)
	for i := 2; i < size-1; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, start+uint32(i))
		if !taken[ip.String()] {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("в подсети %s закончились адреса", subnet)
}

// Params – параметры обфускации для сервера и клиентов.
func (s Settings) AWGParams() map[string]string {
	return map[string]string{"Jc": s.Jc, "Jmin": s.Jmin, "Jmax": s.Jmax, "S1": s.S1, "S2": s.S2, "S3": s.S3, "S4": s.S4,
		"H1": s.H1, "H2": s.H2, "H3": s.H3, "H4": s.H4, "I1": s.I1, "I2": s.I2, "I3": s.I3, "I4": s.I4, "I5": s.I5}
}

// awgDNS для 3.1 дополняет единственный DNS вторым адресом и пишет пару через «, » – как в собственных
// конфигах приложения AmneziaVPN. Остальным значение отдаётся как есть.
func awgDNS(dns string, v31 bool) string {
	dns = strings.TrimSpace(dns)
	if !v31 {
		return dns
	}
	if strings.Contains(dns, ",") {
		return strings.Join(strings.FieldsFunc(dns, func(r rune) bool { return r == ',' || r == ' ' }), ", ")
	}
	if dns == "8.8.8.8" {
		return dns + ", 1.1.1.1"
	}
	return dns + ", 8.8.8.8"
}

// AWGConfig – клиентский файл .conf (AmneziaWG, Keenetic, wg-quick-совместимые клиенты с AmneziaWG).
func (p *Profile) AWGConfig() string {
	if p.AWG == nil {
		return ""
	}
	s := p.S
	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	fmt.Fprintf(&sb, "PrivateKey = %s\nAddress = %s/32\n", p.AWG.PrivateKey, p.AWG.IP)
	if s.DNS != "" {
		fmt.Fprintf(&sb, "DNS = %s\n", awgDNS(s.DNS, p.Kind == AWG3 || s.HeaderKey != ""))
	}
	fmt.Fprintf(&sb, "MTU = %s\n", firstNonEmpty(s.MTU, "1280"))
	for _, k := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"} {
		if v := strings.TrimSpace(s.AWGParams()[k]); v != "" {
			fmt.Fprintf(&sb, "%s = %s\n", k, v)
		}
	}
	if s.HeaderKey != "" {
		fmt.Fprintf(&sb, "HeaderProtectionKey = %s\n", ClientHeaderKey(s.HeaderKey))
		for _, kv := range [][2]string{{"RekeyAfterTime", s.RekeyAfterTime}, {"RekeyTimeout", s.RekeyTimeout},
			{"RejectAfterTime", s.RejectAfterTime}, {"KeepaliveTimeout", s.KeepaliveTimeout},
			{"MaxHandshakeAttempts", s.MaxHandshakeAttempts}, {"ContentPaddingAddition", s.ContentPaddingAddition}} {
			if v := strings.TrimSpace(kv[1]); v != "" {
				fmt.Fprintf(&sb, "%s = %s\n", kv[0], v)
			}
		}
	}
	sb.WriteString("\n[Peer]\n")
	fmt.Fprintf(&sb, "PublicKey = %s\nPresharedKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %s:%d\nPersistentKeepalive = %s\n",
		s.PublicKey, p.AWG.PSK, hostLiteral(p.Host), p.Port, firstNonEmpty(s.Keepalive, "25"))
	return sb.String()
}

// AmneziaURI – ссылка vpn:// для приложения AmneziaVPN: JSON, сжатый как qCompress (4 байта длины + zlib), в base64url.
func (p *Profile) AmneziaURI() string {
	if p.AWG == nil {
		return ""
	}
	s := p.S
	params := s.AWGParams()
	last := map[string]any{
		"client_ip": p.AWG.IP, "client_priv_key": p.AWG.PrivateKey, "client_pub_key": p.AWG.PublicKey,
		"psk_key": p.AWG.PSK, "server_pub_key": s.PublicKey, "config": p.AWGConfig(), "hostName": p.Host,
		"port": p.Port, "mtu": firstNonEmpty(s.MTU, "1280"), "allowed_ips": []string{"0.0.0.0/0", "::/0"},
		"persistent_keep_alive": firstNonEmpty(s.Keepalive, "25"),
	}
	container := "amnezia-awg"
	if p.Kind == AWG3 || s.HeaderKey != "" {
		container = "amnezia-awg2" // родной контейнер 3.1; под старым именем приложение подписывает его как Legacy
	}
	awgBlock := map[string]any{"last_config": "", "port": strconv.Itoa(p.Port), "transport_proto": "udp"}
	for k, v := range params {
		if strings.TrimSpace(v) != "" {
			awgBlock[k] = v
			last[k] = v
		}
	}
	if s.HeaderKey != "" {
		// приложение определяет версию 3.1 по ключу защиты заголовков и protocol_version
		awgBlock["HeaderProtectionKey"] = ClientHeaderKey(s.HeaderKey)
		awgBlock["protocol_version"] = "3.1"
		last["HeaderProtectionKey"] = ClientHeaderKey(s.HeaderKey)
		last["protocol_version"] = "3.1"
	}
	lastJSON, _ := json.Marshal(last)
	awgBlock["last_config"] = string(lastJSON)
	root := map[string]any{
		"containers":       []any{map[string]any{"awg": awgBlock, "container": container}},
		"defaultContainer": container,
		"description":      "Kitsune",
		"dns1":             firstNonEmpty(s.DNS, "1.1.1.1"),
		"dns2":             "8.8.8.8",
		"hostName":         p.Host,
	}
	raw, _ := json.Marshal(root)
	var buf bytes.Buffer
	var ln [4]byte
	binary.BigEndian.PutUint32(ln[:], uint32(len(raw)))
	buf.Write(ln[:])
	zw := zlib.NewWriter(&buf)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	return "vpn://" + base64.RawURLEncoding.EncodeToString(buf.Bytes())
}
