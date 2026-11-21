// Package selfsteal – сайт-заглушка на вашем домене для REALITY («self-steal»). REALITY маскируется под этот сайт:
// постороннему, который зайдёт на сервер по домену, показывается настоящая страница с настоящим сертификатом Let's Encrypt,
// а клиенты Kitsune проходят мимо неё. Веб-сервер слушает только 127.0.0.1, наружу его выводит сам Xray.
package selfsteal

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"kitsune/internal/acme"
	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/site"
	"kitsune/internal/stub"
)

// Addr – локальный адрес веб-сервера; он же указывается в REALITY как target (dest).
const Addr = core.DecoyAddr

const settingKey = "selfsteal_domain"

var (
	mu  sync.Mutex
	srv *http.Server
	gen int    // поколение запуска: старые горутины ожидания сертификата не должны запускать сервер заново
	cur string // домен, для которого запущен сервер или идёт ожидание сертификата

)

// Domain – домен self-steal (пусто, если режим выключен).
func Domain() string { return db.GetSetting(settingKey, "") }

// Set включает режим для домена (пустая строка – выключает) и перезапускает веб-сервер, если панель его запускала.
func Set(domain string) error { return db.SetSetting(settingKey, domain) }

// Ensure получает (или находит в кэше) сертификат домена. Нужен свободный порт 80: на нём Let's Encrypt проверяет домен.
func Ensure(domain string) (crt, key string, err error) {
	if err := core.ConfigureACME(); err != nil {
		return "", "", err
	}
	crt, key, _, err = acme.Files(domain)
	return crt, key, err
}

// Apply приводит работающий сервер в соответствие с настройкой. Вызывается при старте панели и после смены домена
// или заглушки. Если домен тот же, сервер не перезапускается: страница подменяется на лету, слушатель остаётся открытым.
func Apply() {
	mu.Lock()
	defer mu.Unlock()
	site.StartLocal() // локальный слушатель для Hysteria (тот же обработчик, что у этого сайта)
	refreshPage()
	d := Domain()
	if d != "" && d == cur {
		return
	}
	gen++
	if srv != nil {
		_ = srv.Close()
		srv = nil
	}
	cur = ""
	if d == "" {
		return
	}
	cur = d
	go run(d, gen)
}

// refreshPage читает выбранную заглушку и соль установки из настроек и делает их текущими для сайта и для Hysteria.
func refreshPage() {
	id := db.GetSetting("stub_site", "")
	if !stub.Exists(id) {
		id = stub.DefaultID
	}
	site.SetPage(stub.HTML(id))
	// Соль читается через LookupSetting: ошибка чтения базы не должна приводить к новой соли поверх старой (страницы и валидаторы
	// сменились бы у всех). Новая соль создаётся только когда настройки действительно нет.
	salt, found, err := db.LookupSetting("stub_salt")
	switch {
	case err != nil:
		return
	case !found || salt == "":
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		salt = hex.EncodeToString(b)
		if db.SetSetting("stub_salt", salt) != nil {
			return
		}
	}
	site.SetSalt(salt)
}

// fail сбрасывает состояние, если сервер не запустился или остановился сам: следующий Apply поднимет его заново.
func fail(g int) {
	mu.Lock()
	defer mu.Unlock()
	if g == gen {
		srv, cur = nil, ""
	}
}

func run(domain string, g int) {
	// Сертификат могут выпускать долго (DNS, порт 80): пробуем, пока не получится или режим не изменят.
	for {
		crt, key, err := Ensure(domain)
		if err == nil {
			mu.Lock()
			if g != gen {
				mu.Unlock()
				return
			}
			s := newServer(Addr, crt, key)
			srv = s
			mu.Unlock()
			ln, e := net.Listen("tcp", Addr)
			if e != nil {
				fail(g)
				return
			}
			_ = s.ServeTLS(ln, "", "")
			fail(g)
			return
		}
		select {
		case <-time.After(60 * time.Second):
		}
		mu.Lock()
		stale := g != gen
		mu.Unlock()
		if stale {
			return
		}
	}
}

func newServer(addr, crt, key string) *http.Server {
	return &http.Server{Addr: addr, Handler: site.Handler(), ReadHeaderTimeout: 10 * time.Second, DisableGeneralOptionsHandler: true,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: reload(crt, key)}}
}

// reload читает сертификат с диска заново, когда файл обновился (продление Let's Encrypt).
func reload(crt, key string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	var mu sync.Mutex
	var cur *tls.Certificate
	var mod time.Time
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		st, err := os.Stat(crt)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		defer mu.Unlock()
		if cur != nil && st.ModTime().Equal(mod) {
			return cur, nil
		}
		c, err := tls.LoadX509KeyPair(crt, key)
		if err != nil {
			return nil, err
		}
		cur, mod = &c, st.ModTime()
		return cur, nil
	}
}

// Check проверяет работу сервера изнутри: заходит на него с нужным именем и смотрит версию TLS и HTTP/2.
func Check(domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	d := tls.Dialer{Config: &tls.Config{ServerName: domain, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS13}}
	c, err := d.DialContext(ctx, "tcp", Addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if st := c.(*tls.Conn).ConnectionState(); st.NegotiatedProtocol != "h2" {
		return errors.New("сайт-заглушка не отвечает по HTTP/2")
	}
	return nil
}
