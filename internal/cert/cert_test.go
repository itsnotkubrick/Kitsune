package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readCert(t *testing.T) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(SelfPaths().CertFile)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(data)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSelfSignedHasNoProductName(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := EnsureSelfSigned("203.0.113.5"); err != nil {
		t.Fatal(err)
	}
	c := readCert(t)
	if len(c.Subject.Organization) != 0 || c.Subject.CommonName != "203.0.113.5" {
		t.Fatalf("Subject: %v", c.Subject)
	}
	if len(c.Issuer.Organization) != 0 {
		t.Fatalf("Issuer: %v", c.Issuer)
	}
}

func TestOldCertWithProductNameIsReissued(t *testing.T) {
	t.Chdir(t.TempDir())
	host := "203.0.113.5"
	if err := os.MkdirAll(Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host, Organization: []string{"Kitsune"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 0, 180)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	p := SelfPaths()
	_ = os.WriteFile(p.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	_ = os.WriteFile(p.KeyFile, []byte("old"), 0o600)
	if _, err := EnsureSelfSigned(host); err != nil {
		t.Fatal(err)
	}
	if c := readCert(t); len(c.Subject.Organization) != 0 {
		t.Fatalf("старый сертификат не перевыпущен: %v", c.Subject)
	}
	// чистый сертификат повторно не выпускается
	before, _ := os.ReadFile(p.CertFile)
	if _, err := EnsureSelfSigned(host); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(Dir, "self.crt"))
	if string(before) != string(after) {
		t.Fatal("действующий сертификат без O=Kitsune перевыпущен зря")
	}
}
