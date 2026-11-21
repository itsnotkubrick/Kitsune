package check

import (
	"crypto/x509"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func okProbes() pathProbes {
	return pathProbes{
		lookup:    func(string) ([]string, error) { return []string{"203.0.113.5"}, nil },
		dial:      func(string) error { return nil },
		tlsOK:     func(string, string, bool) error { return nil },
		localOpen: func(int) bool { return true },
	}
}

func base() pathInput {
	return pathInput{Tag: "reality", Port: 443, TLS: true, SNI: "www.example.com", Host: "vpn.example.net", Reaching: true}
}

func TestClassifyPathLayers(t *testing.T) {
	cases := []struct {
		name  string
		mod   func(*pathInput, *pathProbes)
		code  string
		level string
	}{
		{"всё проходит", func(*pathInput, *pathProbes) {}, "", OK},
		{"ядро не слушает", func(in *pathInput, _ *pathProbes) { in.Reaching = false }, CodeCoreDown, Bad},
		{"UDP с сервера не проверить", func(in *pathInput, _ *pathProbes) { in.UDP = true }, CodeUnknown, Info},
		{"адрес не задан", func(in *pathInput, _ *pathProbes) { in.Host = "" }, CodeUnknown, Info},
		{"имя не разрешается", func(_ *pathInput, p *pathProbes) {
			p.lookup = func(string) ([]string, error) { return nil, errors.New("no such host") }
		}, CodeDNSFailed, Bad},
		{"для IP DNS не нужен", func(in *pathInput, p *pathProbes) {
			in.Host = "203.0.113.5"
			p.lookup = func(string) ([]string, error) { return nil, errors.New("не должно вызываться") }
		}, "", OK},
		{"таймаут TCP", func(_ *pathInput, p *pathProbes) { p.dial = func(string) error { return timeoutErr{} } }, CodeTCPConnectTimeout, Warn},
		{"отказ в соединении", func(_ *pathInput, p *pathProbes) {
			p.dial = func(string) error {
				return &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
			}
		}, CodeEndpointUnreachable, Bad},
		{"TLS не завершился", func(_ *pathInput, p *pathProbes) {
			p.tlsOK = func(string, string, bool) error { return errors.New("tls: handshake failure") }
		}, CodeTLSFailed, Warn},
		{"сертификат не проходит", func(in *pathInput, p *pathProbes) {
			in.Verify = true
			p.tlsOK = func(string, string, bool) error { return x509.UnknownAuthorityError{} }
		}, CodeCertInvalid, Bad},
		{"без TLS", func(in *pathInput, _ *pathProbes) { in.TLS = false }, "", OK},
	}
	for _, c := range cases {
		in, p := base(), okProbes()
		c.mod(&in, &p)
		r := classifyPath(in, p)
		if r.Code != c.code || r.Level != c.level {
			t.Errorf("%s: код %q уровень %q, ждали %q и %q (%s)", c.name, r.Code, r.Level, c.code, c.level, r.Text)
		}
		if c.code != "" && !strings.Contains(r.Text, "["+c.code+"]") {
			t.Errorf("%s: в тексте нет кода: %s", c.name, r.Text)
		}
	}
}

func TestClassifyPathNeverClaimsBlocking(t *testing.T) {
	for _, code := range []string{CodeTCPConnectTimeout, CodeEndpointUnreachable, CodeTLSFailed} {
		in, p := base(), okProbes()
		switch code {
		case CodeTCPConnectTimeout:
			p.dial = func(string) error { return timeoutErr{} }
		case CodeEndpointUnreachable:
			p.dial = func(string) error { return errors.New("network unreachable") }
		case CodeTLSFailed:
			p.tlsOK = func(string, string, bool) error { return errors.New("eof") }
		}
		txt := strings.ToLower(classifyPath(in, p).Text)
		for _, bad := range []string{"блокиров"} {
			if strings.Contains(txt, bad) {
				t.Errorf("%s: текст утверждает причину («%s»), а проверка с сервера этого не знает: %s", code, bad, txt)
			}
		}
	}
}
