// Package acme получает и продлевает сертификаты Let's Encrypt (HTTP-01 на порту 80) для HTTPS панели
// и для TLS-подключений (TUIC, NaiveProxy, WS, gRPC, Hysteria2…).
package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	xacme "golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"kitsune/internal/site"
)

const cacheDir = "certs/acme"

var (
	mu      sync.Mutex
	mgr     *autocert.Manager
	domains = map[string]bool{}
	email   string
	httpSrv *http.Server
)

func manager() *autocert.Manager {
	if mgr == nil {
		mgr = &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(cacheDir),
			Email:  email,
			HostPolicy: func(_ context.Context, host string) error {
				mu.Lock()
				defer mu.Unlock()
				if domains[strings.ToLower(host)] {
					return nil
				}
				return fmt.Errorf("домен %q не настроен для сертификатов", host)
			},
		}
		// KITSUNE_ACME_DIRECTORY – другой ACME-сервер (например, staging Let's Encrypt для отладки)
		if v := os.Getenv("KITSUNE_ACME_DIRECTORY"); v != "" {
			mgr.Client = &xacme.Client{DirectoryURL: v}
		}
	}
	return mgr
}

// Configure задаёт почту и список доменов, для которых разрешено выпускать сертификаты.
func Configure(contact string, hosts []string) {
	mu.Lock()
	email = strings.TrimSpace(contact)
	domains = map[string]bool{}
	for _, h := range hosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			domains[h] = true
		}
	}
	m := manager()
	m.Email = email
	mu.Unlock()
}

// notFoundNginx – ответ порта 80 на всё, кроме проверки Let's Encrypt: то же 404 «nginx», что отдаёт панель.
// Без него autocert отвечает редиректом «Use HTTPS» и этим отличается от обычного веб-сервера.
func notFoundNginx(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Server", "nginx")
	h.Set("Content-Type", "text/html")
	h.Set("Content-Length", strconv.Itoa(len(site.NotFoundBody)))
	w.WriteHeader(http.StatusNotFound)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(site.NotFoundBody))
	}
}

// StartChallenge запускает слушатель порта 80 для проверки HTTP-01 (идемпотентно).
func StartChallenge(addr string) error {
	mu.Lock()
	defer mu.Unlock()
	if httpSrv != nil {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("порт 80 нужен Let's Encrypt для проверки домена, но недоступен: %w", err)
	}
	httpSrv = &http.Server{Handler: manager().HTTPHandler(http.HandlerFunc(notFoundNginx)), ReadHeaderTimeout: 10 * time.Second, DisableGeneralOptionsHandler: true}
	go func() { _ = httpSrv.Serve(ln) }()
	return nil
}

func StopChallenge() {
	mu.Lock()
	defer mu.Unlock()
	if httpSrv != nil {
		_ = httpSrv.Close()
		httpSrv = nil
	}
}

// TLSConfig – настройки TLS для HTTPS-сервера панели: сертификат берётся и обновляется автоматически.
func TLSConfig() *tls.Config {
	mu.Lock()
	defer mu.Unlock()
	cfg := manager().TLSConfig()
	cfg.MinVersion = tls.VersionTLS12
	return cfg
}

// Files получает (при необходимости выпускает) сертификат домена и сохраняет его в файлы для ядер.
func Files(domain string) (crt, key string, changed bool, err error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || net.ParseIP(domain) != nil {
		return "", "", false, errors.New("для Let's Encrypt нужен домен, а не IP-адрес")
	}
	mu.Lock()
	ok := domains[domain]
	m := manager()
	mu.Unlock()
	if !ok {
		return "", "", false, fmt.Errorf("домен %s не добавлен в список для сертификатов", domain)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	type result struct {
		c   *tls.Certificate
		err error
	}
	ch := make(chan result, 1)
	go func() {
		// Просим ECDSA-сертификат (P-256): он компактнее и подходит всем ядрам.
		c, err := m.GetCertificate(&tls.ClientHelloInfo{
			ServerName: domain, SupportedProtos: []string{"h2"},
			SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
			SupportedCurves:   []tls.CurveID{tls.CurveP256},
			SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
			CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_AES_128_GCM_SHA256},
		})
		ch <- result{c, err}
	}()
	var c *tls.Certificate
	select {
	case r := <-ch:
		c, err = r.c, r.err
	case <-ctx.Done():
		err = errors.New("Let's Encrypt не ответил за 90 секунд (проверьте, что домен указывает на сервер, а порт 80 открыт)")
	}
	if err != nil {
		return "", "", false, err
	}
	var pemCert []byte
	for _, der := range c.Certificate {
		pemCert = append(pemCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	var keyDER []byte
	var keyType string
	switch k := c.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		keyDER, err = x509.MarshalECPrivateKey(k)
		keyType = "EC PRIVATE KEY"
	case *rsa.PrivateKey:
		keyDER = x509.MarshalPKCS1PrivateKey(k)
		keyType = "RSA PRIVATE KEY"
	default:
		err = errors.New("неподдерживаемый тип ключа")
	}
	if err != nil {
		return "", "", false, err
	}
	if err := os.MkdirAll("certs", 0o700); err != nil {
		return "", "", false, err
	}
	abs, _ := filepath.Abs("certs")
	crt = filepath.Join(abs, "le-"+domain+".crt")
	key = filepath.Join(abs, "le-"+domain+".key")
	old, _ := os.ReadFile(crt)
	if string(old) != string(pemCert) {
		changed = true
		if err := os.WriteFile(crt, pemCert, 0o644); err != nil {
			return "", "", false, err
		}
		if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: keyDER}), 0o600); err != nil {
			return "", "", false, err
		}
	}
	return crt, key, changed, nil
}

// Domains – настроенные домены (для проверок).
func Domains() []string {
	mu.Lock()
	defer mu.Unlock()
	var out []string
	for d := range domains {
		out = append(out, d)
	}
	return out
}
