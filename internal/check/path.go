package check

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/proto"
)

// Коды причин сетевого пути. Это наблюдения этой проверки, а не диагноз: «заблокировано оператором» по ним не выводится.
const (
	CodeDNSFailed           = "DNS_FAILED"
	CodeEndpointUnreachable = "ENDPOINT_UNREACHABLE"
	CodeTCPConnectTimeout   = "TCP_CONNECT_TIMEOUT"
	CodeTLSFailed           = "TLS_FAILED"
	CodeCertInvalid         = "CERT_INVALID"
	CodeCoreDown            = "CORE_DOWN"
	CodeProtocolHandshake   = "PROTOCOL_HANDSHAKE_FAILED"
	CodeUnknown             = "UNKNOWN"
)

const pathGroup = "Сетевой путь"

// pathProbes – то, чем проверка обращается к сети; подменяется в тестах.
type pathProbes struct {
	lookup    func(host string) ([]string, error)
	dial      func(addr string) error
	tlsOK     func(addr, sni string, verify bool) error
	localOpen func(port int) bool
}

func realPathProbes() pathProbes {
	return pathProbes{
		lookup: net.LookupHost,
		dial: func(addr string) error {
			c, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				return err
			}
			return c.Close()
		},
		tlsOK: func(addr, sni string, verify bool) error {
			if verify {
				return verifiedTLS(addr, sni)
			}
			_, err := tlsLook(addr, sni, nil)
			return err
		},
		localOpen: tcpListens,
	}
}

// pathInput – один включённый TCP-подключение и всё, что нужно знать для проверки по слоям.
type pathInput struct {
	Tag      string
	Port     int
	UDP      bool
	TLS      bool   // рукопожатие TLS на этом порту проверяется
	Verify   bool   // сертификат должен проходить проверку (Let's Encrypt или свой)
	SNI      string // имя для TLS; пусто – адрес сервера
	Host     string // публичный адрес сервера (домен или IP); пусто – не задан
	Reaching bool   // порт уже слушается локально
}

type pathResult struct {
	Level string
	Code  string
	Text  string
}

// classifyPath идёт по слоям и останавливается на первом, который не прошёл.
func classifyPath(in pathInput, p pathProbes) pathResult {
	name := fmt.Sprintf("%s (порт %d/%s)", in.Tag, in.Port, map[bool]string{true: "udp", false: "tcp"}[in.UDP])
	if !in.Reaching {
		return pathResult{Bad, CodeCoreDown, fmt.Sprintf("[%s] %s: слой «ядро»: порт не слушается даже на самом сервере (ядро не запущено или не приняло конфиг)", CodeCoreDown, name)}
	}
	if in.UDP {
		return pathResult{Info, CodeUnknown, fmt.Sprintf("[%s] %s: UDP с самого сервера не проверить; порт слушается, доступность из вашей сети покажет только проверка с клиента", CodeUnknown, name)}
	}
	if in.Host == "" {
		return pathResult{Info, CodeUnknown, fmt.Sprintf("[%s] %s: адрес сервера не задан (укажите его в «Настройках»), слои DNS и публичного адреса не проверены", CodeUnknown, name)}
	}
	isIP := net.ParseIP(in.Host) != nil
	if !isIP {
		addrs, err := p.lookup(in.Host)
		if err != nil || len(addrs) == 0 {
			return pathResult{Bad, CodeDNSFailed, fmt.Sprintf("[%s] %s: слой «DNS»: имя %s не разрешается, клиенты не найдут сервер", CodeDNSFailed, name, in.Host)}
		}
	}
	addr := net.JoinHostPort(in.Host, strconv.Itoa(in.Port))
	if err := p.dial(addr); err != nil {
		var ne net.Error
		var refused bool
		var op *net.OpError
		if errors.As(err, &op) {
			refused = errors.Is(op.Err, syscall.ECONNREFUSED)
		}
		if errors.As(err, &ne) && ne.Timeout() {
			return pathResult{Warn, CodeTCPConnectTimeout, fmt.Sprintf("[%s] %s: слой «TCP»: соединение с публичным адресом не установилось за 5 с. Порт локально открыт, поэтому причина может быть в файрволе хостера или в том, что сервер не может подключиться к собственному публичному адресу. Проверьте с другого устройства", CodeTCPConnectTimeout, name)}
		}
		if refused {
			return pathResult{Bad, CodeEndpointUnreachable, fmt.Sprintf("[%s] %s: слой «TCP»: публичный адрес отказывает в соединении, хотя порт локально открыт. Проверьте файрвол и привязку порта", CodeEndpointUnreachable, name)}
		}
		return pathResult{Warn, CodeEndpointUnreachable, fmt.Sprintf("[%s] %s: слой «TCP»: публичный адрес недоступен (%v)", CodeEndpointUnreachable, name, err)}
	}
	if in.TLS {
		sni := in.SNI
		if sni == "" {
			sni = in.Host
		}
		if err := p.tlsOK(addr, sni, in.Verify && !isIP); err != nil {
			var inv x509.CertificateInvalidError
			var host x509.HostnameError
			var unk x509.UnknownAuthorityError
			if errors.As(err, &inv) || errors.As(err, &host) || errors.As(err, &unk) || strings.Contains(err.Error(), "certificate") {
				return pathResult{Bad, CodeCertInvalid, fmt.Sprintf("[%s] %s: слой «TLS»: сертификат не проходит проверку (%v). Исправьте сертификат, не отключайте проверку", CodeCertInvalid, name, err)}
			}
			return pathResult{Warn, CodeTLSFailed, fmt.Sprintf("[%s] %s: слой «TLS»: рукопожатие не завершилось (%v)", CodeTLSFailed, name, err)}
		}
		return pathResult{OK, "", fmt.Sprintf("%s: путь проходит: DNS → TCP → TLS", name)}
	}
	return pathResult{OK, "", fmt.Sprintf("%s: путь проходит: DNS → TCP", name)}
}

// tlsVerified делает рукопожатие с обычной проверкой цепочки и имени.
func tlsVerified(addr, sni string) (tls.ConnectionState, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	raw, err := d.Dial("tcp", addr)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(8 * time.Second))
	c := tls.Client(raw, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12})
	if err := c.Handshake(); err != nil {
		return tls.ConnectionState{}, err
	}
	return c.ConnectionState(), nil
}

// verifiedTLS – рукопожатие с обычной проверкой сертификата.
func verifiedTLS(addr, sni string) error {
	_, err := tlsVerified(addr, sni)
	return err
}

func tlsUsed(k proto.Kind) bool {
	switch k {
	case proto.VlessReality, proto.VlessXHTTP, proto.VlessWS, proto.TrojanGRPC, proto.VmessWS, proto.Naive:
		return true
	}
	return false
}

// checkPath – слой за слоем: ядро → DNS → публичный TCP → TLS. Проверка идёт с самого сервера: доступность из сети
// пользователя она не показывает, поэтому причина вида «ограничения оператора» здесь не выводится.
func checkPath(add adder) {
	if db.DB == nil {
		return
	}
	inbounds, err := db.GetInbounds()
	if err != nil || len(inbounds) == 0 {
		return
	}
	env := core.PublicEnv()
	host := db.GetSetting("public_host", "")
	probes := realPathProbes()
	shown := false
	for _, ib := range inbounds {
		if !ib.Enable {
			continue
		}
		info, _ := proto.Get(proto.Kind(ib.Kind))
		s := proto.ParseSettings(ib.Settings)
		in := pathInput{Tag: ib.Tag, Port: inboundPort(ib, env), Host: host, SNI: s.SNI}
		if info != nil && info.Net == "udp" {
			in.UDP = true
		}
		kind := proto.Kind(ib.Kind)
		in.TLS = tlsUsed(kind)
		in.Verify = in.TLS && kind != proto.VlessReality && kind != proto.VlessXHTTP && (s.CertMode == "acme" || s.CertMode == "custom")
		if kind == proto.VlessReality || kind == proto.VlessXHTTP {
			in.SNI = s.SNI
		} else {
			in.SNI = host
		}
		in.Reaching = probes.localOpen(in.Port) || in.UDP
		if in.UDP {
			in.Reaching = true // порт UDP локально не пробуется, это решают проверки «Подключения»
		}
		r := classifyPath(in, probes)
		add(pathGroup, r.Level, r.Text, "")
		shown = true
	}
	if shown {
		add(pathGroup, Info, "Проверка идёт с самого сервера: доступность из вашей сети она не показывает. Если здесь всё в порядке, а клиент не подключается, проверьте путь с устройства клиента (ссылка проверки стабильности соединения в «Здоровье»).", "")
	}
}
