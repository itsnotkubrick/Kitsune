// Package cert выпускает и хранит самоподписанный сертификат панели для TLS-подключений (WS, gRPC, Hysteria2, TUIC…).
package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const Dir = "certs"

// RenewBefore – за сколько до окончания сертификат выпускается заново.
const RenewBefore = 20 * 24 * time.Hour

type Pair struct {
	CertFile string
	KeyFile  string
}

func SelfPaths() Pair {
	return Pair{CertFile: filepath.Join(Dir, "self.crt"), KeyFile: filepath.Join(Dir, "self.key")}
}

// EnsureSelfSigned создаёт сертификат на 180 дней для host (IP или домен), если его ещё нет
// или он выпущен на другой адрес. Возвращает пути в виде абсолютных (их читает ядро).
func EnsureSelfSigned(host string) (Pair, error) {
	p := SelfPaths()
	abs := Pair{}
	abs.CertFile, _ = filepath.Abs(p.CertFile)
	abs.KeyFile, _ = filepath.Abs(p.KeyFile)

	if data, err := os.ReadFile(p.CertFile); err == nil {
		if blk, _ := pem.Decode(data); blk != nil {
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil && c.NotAfter.After(time.Now().Add(RenewBefore)) && covers(c, host) && !hasProductMark(c) {
				if _, err := os.Stat(p.KeyFile); err == nil {
					return abs, nil
				}
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return abs, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host}, // без Organization: имя продукта в сертификате видит любой, кто откроет TLS на порт
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, 180), // Chromium и NaiveProxy отвергают слишком долгие сертификаты (с 2026 года базовый предел 200 дней)
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else if host != "" {
		tpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return abs, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return abs, err
	}
	if err := os.MkdirAll(Dir, 0o700); err != nil {
		return abs, err
	}
	if err := os.WriteFile(p.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return abs, err
	}
	if err := os.WriteFile(p.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return abs, err
	}
	return abs, nil
}

// hasProductMark узнаёт сертификат, выпущенный прежними версиями с O=Kitsune: его перевыпускают без имени продукта.
func hasProductMark(c *x509.Certificate) bool {
	for _, o := range c.Subject.Organization {
		if strings.EqualFold(o, "Kitsune") {
			return true
		}
	}
	return false
}

func covers(c *x509.Certificate, host string) bool {
	if host == "" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, a := range c.IPAddresses {
			if a.Equal(ip) {
				return true
			}
		}
		return false
	}
	return c.VerifyHostname(host) == nil
}

// Fingerprint – SHA-256 сертификата (hex, нижний регистр): им клиенты закрепляют самоподписанный сертификат.
func Fingerprint(certFile string) string {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return ""
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		return ""
	}
	sum := sha256.Sum256(blk.Bytes)
	return hex.EncodeToString(sum[:])
}

// NeedsRenewal сообщает, что самоподписанный сертификат скоро истечёт (или его нет).
func NeedsRenewal() bool {
	data, err := os.ReadFile(SelfPaths().CertFile)
	if err != nil {
		return false // сертификата нет – выпустится при первой необходимости
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		return true
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	return err != nil || time.Until(c.NotAfter) < RenewBefore
}
