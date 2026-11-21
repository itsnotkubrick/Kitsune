package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// Сертификаты Let's Encrypt на IP-адрес: профиль shortlived (около 6 суток), проверка HTTP-01 на порту 80.
// Автоматически обновляются, когда остаётся меньше IPRenewBefore.
const (
	IPRenewBefore = 72 * time.Hour
	ipDir         = "certs/acme-ip"
)

type ipUser struct {
	reg *registration.Resource
	key crypto.PrivateKey
}

func (u *ipUser) GetEmail() string {
	return ""
}
func (u *ipUser) GetRegistration() *registration.Resource { return u.reg }
func (u *ipUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

type emailUser struct {
	*ipUser
	email string
}

func (u *emailUser) GetEmail() string { return u.email }

var ipMu sync.Mutex

func IPPaths(ip string) (crt, key string) {
	abs, _ := filepath.Abs("certs")
	return filepath.Join(abs, "le-ip-"+ip+".crt"), filepath.Join(abs, "le-ip-"+ip+".key")
}

func accountKey() (*ecdsa.PrivateKey, error) {
	if err := os.MkdirAll(ipDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(ipDir, "account.key")
	if b, err := os.ReadFile(path); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
				return k, nil
			}
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, _ := x509.MarshalECPrivateKey(k)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

// certExpiry возвращает срок окончания сертификата в файле (нулевое время – файла нет или он не читается).
func CertExpiry(crtFile string) time.Time {
	b, err := os.ReadFile(crtFile)
	if err != nil {
		return time.Time{}
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return time.Time{}
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return time.Time{}
	}
	return c.NotAfter
}

// IPFiles возвращает файлы сертификата на IP-адрес; выпускает новый, если его нет или срок подходит к концу.
// changed – файлы обновились. Для выпуска нужен свободный порт 80.
func IPFiles(ip, contact string) (crt, key string, changed bool, err error) {
	if net.ParseIP(ip) == nil {
		return "", "", false, errors.New("нужен IP-адрес")
	}
	ipMu.Lock()
	defer ipMu.Unlock()
	crt, key = IPPaths(ip)
	if exp := CertExpiry(crt); !exp.IsZero() && time.Until(exp) > IPRenewBefore {
		if _, e := os.Stat(key); e == nil {
			return crt, key, false, nil
		}
	}
	ak, err := accountKey()
	if err != nil {
		return "", "", false, err
	}
	var user registration.User = &ipUser{key: ak}
	if contact != "" {
		user = &emailUser{ipUser: &ipUser{key: ak}, email: contact}
	}
	cfg := lego.NewConfig(user)
	cfg.CADirURL = lego.LEDirectoryProduction
	if v := os.Getenv("KITSUNE_ACME_DIRECTORY"); v != "" {
		cfg.CADirURL = v
	}
	cfg.Certificate.KeyType = certcrypto.EC256
	cl, err := lego.NewClient(cfg)
	if err != nil {
		return "", "", false, err
	}
	// HTTP-01: слушаем порт 80 сами, на время выпуска.
	if err := cl.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80")); err != nil {
		return "", "", false, err
	}
	reg, err := cl.Registration.ResolveAccountByKey()
	if err != nil {
		reg, err = cl.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return "", "", false, fmt.Errorf("регистрация в Let's Encrypt: %w", err)
		}
	}
	switch u := user.(type) {
	case *ipUser:
		u.reg = reg
	case *emailUser:
		u.reg = reg
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	type res struct {
		c *certificate.Resource
		e error
	}
	ch := make(chan res, 1)
	go func() {
		c, e := cl.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{ip}, Bundle: true, Profile: "shortlived"})
		ch <- res{c, e}
	}()
	var out *certificate.Resource
	select {
	case r := <-ch:
		out, err = r.c, r.e
	case <-ctx.Done():
		err = errors.New("Let's Encrypt не ответил за 3 минуты")
	}
	if err != nil {
		return "", "", false, fmt.Errorf("Let's Encrypt не выдал сертификат на IP %s (проверьте, что порт 80/tcp открыт снаружи и свободен): %w", ip, err)
	}
	if err := os.MkdirAll(filepath.Dir(crt), 0o700); err != nil {
		return "", "", false, err
	}
	if err := os.WriteFile(crt, out.Certificate, 0o644); err != nil {
		return "", "", false, err
	}
	if err := os.WriteFile(key, out.PrivateKey, 0o600); err != nil {
		return "", "", false, err
	}
	return crt, key, true, nil
}

var (
	reloadMu    sync.Mutex
	reloadCache = map[string]*reloadEntry{}
)

type reloadEntry struct {
	cert *tls.Certificate
	mod  time.Time
}

// IPTLSConfig – настройки TLS для HTTPS панели: сертификат перечитывается с диска, когда он обновился.
func IPTLSConfig(ip string) *tls.Config {
	crt, key := IPPaths(ip)
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			st, err := os.Stat(crt)
			if err != nil {
				return nil, err
			}
			reloadMu.Lock()
			defer reloadMu.Unlock()
			if e := reloadCache[crt]; e != nil && e.mod.Equal(st.ModTime()) {
				return e.cert, nil
			}
			c, err := tls.LoadX509KeyPair(crt, key)
			if err != nil {
				return nil, err
			}
			reloadCache[crt] = &reloadEntry{cert: &c, mod: st.ModTime()}
			return &c, nil
		},
	}
}
