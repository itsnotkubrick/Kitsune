package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeIPCert(t *testing.T, ip string, notAfter time.Time) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: ip},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, IPAddresses: []net.IP{net.ParseIP(ip)}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(k)
	crt, key := IPPaths(ip)
	if err := os.MkdirAll(filepath.Dir(crt), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
}

func TestIPCertFreshIsNotReissuedAndReloads(t *testing.T) {
	t.Chdir(t.TempDir())
	writeIPCert(t, "203.0.113.9", time.Now().Add(5*24*time.Hour))
	crt, _, changed, err := IPFiles("203.0.113.9", "")
	if err != nil || changed || crt == "" {
		t.Fatalf("действующий сертификат трогать не нужно: changed=%v err=%v", changed, err)
	}
	cfg := IPTLSConfig("203.0.113.9")
	c1, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	writeIPCert(t, "203.0.113.9", time.Now().Add(6*24*time.Hour)) // «продление»: файл заменён
	c2, _ := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if c1.Leaf == c2.Leaf && string(c1.Certificate[0]) == string(c2.Certificate[0]) {
		t.Fatal("после замены файла отдавался старый сертификат")
	}
}

func TestIPCertExpiry(t *testing.T) {
	t.Chdir(t.TempDir())
	if !CertExpiry("нет-файла").IsZero() {
		t.Fatal("нет файла – нулевое время")
	}
	if _, _, _, err := IPFiles("not-an-ip", ""); err == nil {
		t.Fatal("не IP должен отклоняться")
	}
}
