package masking

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func testCert(t *testing.T, names ...string) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func serve(t *testing.T, cfg *tls.Config) (host, port string) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	return h, p
}

func TestCheckAcceptsTLS13H2(t *testing.T) {
	host, port := serve(t, &tls.Config{Certificates: []tls.Certificate{testCert(t, "good.example.com")}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}})
	Port = port
	t.Cleanup(func() { Port = "443" })
	if _, ok := Check(context.Background(), host, "good.example.com"); !ok {
		t.Fatal("сайт с TLS 1.3 и h2 должен подходить")
	}
}

func TestCheckRejectsTLS12AndNoH2(t *testing.T) {
	host, port := serve(t, &tls.Config{Certificates: []tls.Certificate{testCert(t, "old.example.com")}, MaxVersion: tls.VersionTLS12, NextProtos: []string{"h2"}})
	Port = port
	t.Cleanup(func() { Port = "443" })
	if _, ok := Check(context.Background(), host, "old.example.com"); ok {
		t.Fatal("TLS 1.2 не подходит для REALITY")
	}
	host2, port2 := serve(t, &tls.Config{Certificates: []tls.Certificate{testCert(t, "h1.example.com")}, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}})
	Port = port2
	if _, ok := Check(context.Background(), host2, "h1.example.com"); ok {
		t.Fatal("без HTTP/2 сайт не подходит")
	}
}

func TestAllowed(t *testing.T) {
	for name, want := range map[string]bool{"dl.google.com": true, "www.apple.com": false, "yandex.ru": false, "*.example.com": false,
		"1.2.3.4": false, "localhost": false, "www.samsung.com": true, "update.microsoft.com": false} {
		if allowed(name) != want {
			t.Errorf("allowed(%q) = %v, ожидалось %v", name, !want, want)
		}
	}
}
