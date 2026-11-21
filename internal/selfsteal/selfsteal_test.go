package selfsteal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kitsune/internal/db"
	"kitsune/internal/site"
	"kitsune/internal/stub"
)

func TestServerServesStubOverTLS13AndH2(t *testing.T) {
	dir := t.TempDir()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vpn.example.com"}, DNSNames: []string{"vpn.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	kd, _ := x509.MarshalECPrivateKey(k)
	crt, key := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	os.WriteFile(crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(ln.Addr().String(), crt, key)
	go s.ServeTLS(ln, "", "")
	defer s.Close()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: "vpn.example.com", NextProtos: []string{"h2"}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	st := conn.ConnectionState()
	conn.Close()
	if st.Version != tls.VersionTLS13 || st.NegotiatedProtocol != "h2" {
		t.Fatalf("нужны TLS 1.3 и HTTP/2 (так REALITY принимает сайт), получено: версия %x, протокол %q", st.Version, st.NegotiatedProtocol)
	}
	// обычным клиентом по HTTP/1.1: страница-заглушка
	c2, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: "vpn.example.com", InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	io.WriteString(c2, "GET / HTTP/1.1\r\nHost: vpn.example.com\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(c2)
	if !strings.Contains(string(b), "200 OK") || !strings.Contains(string(b), "<html") {
		t.Fatalf("ожидалась страница-заглушка: %.200s", b)
	}
}

// Сайт на домене показывает ту же страницу, что отдаёт Hysteria: она берётся из stub_site при каждом Apply.
func TestHandlerFollowsStubSetting(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	for _, id := range []string{"studio", "blog", "nginx"} {
		_ = db.SetSetting("stub_site", id)
		refreshPage()
		rec := httptest.NewRecorder()
		site.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		if rec.Body.String() != stub.HTML(id) {
			t.Fatalf("для %s сайт на домене отдал другую страницу", id)
		}
	}
}

// Смена заглушки при том же домене не перезапускает сервер: слушатель остаётся, страница подменяется на лету.
func TestApplyKeepsServerOnSameDomain(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	s := &http.Server{}
	mu.Lock()
	srv, cur = s, "a.example"
	mu.Unlock()
	_ = Set("a.example")
	for _, id := range []string{"docs", "blog"} {
		_ = db.SetSetting("stub_site", id)
		Apply()
		mu.Lock()
		same := srv == s
		mu.Unlock()
		if !same {
			t.Fatalf("для %s сервер был перезапущен", id)
		}
		rec := httptest.NewRecorder()
		site.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		if rec.Body.String() != stub.HTML(id) {
			t.Fatalf("для %s страница не обновилась", id)
		}
	}
	_ = Set("")
	Apply() // домен убрали: сервер останавливается
	mu.Lock()
	defer mu.Unlock()
	if srv != nil || cur != "" {
		t.Fatal("сервер должен остановиться, когда домен убран")
	}
}

// Ошибка чтения базы не должна менять соль: иначе страницы и валидаторы сменились бы у всех после перезапуска.
func TestRefreshPageKeepsSaltOnReadError(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	refreshPage()
	probe := func() string {
		rec := httptest.NewRecorder()
		site.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		return rec.Header().Get("ETag")
	}
	before := probe()
	salt := db.GetSetting("stub_salt", "")
	if before == "" || salt == "" {
		t.Fatal("соль и валидатор должны появиться при первом запуске")
	}
	_ = db.DB.Close() // чтение настройки теперь возвращает ошибку
	refreshPage()
	if got := probe(); got != before {
		t.Fatalf("после ошибки чтения валидатор изменился: %s -> %s", before, got)
	}
}
