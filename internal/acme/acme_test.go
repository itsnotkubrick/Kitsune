package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// Кладём готовый сертификат в кэш autocert: тогда выпускать (и обращаться к Let's Encrypt) не нужно.
func seedCache(t *testing.T, domain string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 3, 0)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	if err := autocert.DirCache(cacheDir).Put(context.Background(), domain, data); err != nil {
		t.Fatal(err)
	}
}

func TestFilesExportsCachedCertificate(t *testing.T) {
	t.Chdir(t.TempDir())
	mgr = nil
	domain := "vpn.example.org"
	seedCache(t, domain)
	Configure("me@example.org", []string{domain})
	crt, key, changed, err := Files(domain)
	if err != nil || !changed {
		t.Fatalf("Files: %v changed=%v", err, changed)
	}
	// файлы должны быть пригодны для ядер: пара ключ/сертификат загружается
	if _, err := tls.LoadX509KeyPair(crt, key); err != nil {
		t.Fatalf("пара не загружается: %v", err)
	}
	if st, _ := os.Stat(key); st.Mode().Perm() != 0o600 {
		t.Fatalf("права на ключ %v, нужно 600", st.Mode().Perm())
	}
	if _, _, changed, _ := Files(domain); changed {
		t.Fatal("повторная выгрузка того же сертификата не должна менять файлы")
	}
}

func TestRejectsUnknownDomainsAndIPs(t *testing.T) {
	t.Chdir(t.TempDir())
	mgr = nil
	Configure("", []string{"ok.example.org"})
	if _, _, _, err := Files("evil.example.org"); err == nil || !strings.Contains(err.Error(), "не добавлен") {
		t.Fatalf("чужой домен должен отклоняться: %v", err)
	}
	if _, _, _, err := Files("203.0.113.5"); err == nil {
		t.Fatal("для IP сертификат Let's Encrypt не выпускается")
	}
	if err := manager().HostPolicy(context.Background(), "evil.example.org"); err == nil {
		t.Fatal("политика хостов должна отклонять чужие домены")
	}
}

func TestNotFoundNginx(t *testing.T) {
	rec := httptest.NewRecorder()
	notFoundNginx(rec, httptest.NewRequest("GET", "http://203.0.113.5/", nil))
	if rec.Code != 404 || rec.Header().Get("Server") != "nginx" || !strings.Contains(rec.Body.String(), "nginx") {
		t.Errorf("порт 80 должен отвечать как nginx: %d %v %q", rec.Code, rec.Header(), rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("редиректа на HTTPS быть не должно: %q", loc)
	}
	head := httptest.NewRecorder()
	notFoundNginx(head, httptest.NewRequest("HEAD", "http://203.0.113.5/", nil))
	if head.Body.Len() != 0 {
		t.Error("на HEAD тела быть не должно")
	}
}
