package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"kitsune/internal/acme"
	"kitsune/internal/cert"
	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/events"
)

var (
	panelTLSMu  sync.Mutex
	panelTLSSrv *http.Server
	panelCfg    atomic.Pointer[core.PanelTLS] // нынешние настройки для обработчика обычного HTTP
	panelRoot   http.Handler                  // сам интерфейс панели (gin)
)

// plainHandler keeps health checks on HTTP and refuses subscription data over
// plaintext when panel TLS is configured. A redirect cannot protect a key
// already sent in the original URL.
func plainHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := panelCfg.Load()
		if cfg != nil && cfg.Mode != "" && cfg.Mode != "off" && !isSecureHTTP(r) && r.URL.Path != "/api/health" {
			if strings.HasPrefix(r.URL.Path, "/sub/") {
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "HTTPS required", http.StatusForbidden)
				return
			}
			if cfg.Redirect {
				http.Redirect(w, r, panelHTTPSBase(cfg, requestHost(r))+r.URL.RequestURI(), http.StatusTemporaryRedirect)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func panelHTTPSBase(cfg *core.PanelTLS, host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else {
		host = strings.Trim(host, "[]")
	}
	if (cfg.Mode == "acme" || cfg.Mode == "acme-ip") && cfg.Domain != "" {
		host = cfg.Domain
	}
	return "https://" + net.JoinHostPort(host, strconv.Itoa(cfg.Port))
}

// applyPanelTLS запускает, перезапускает или останавливает HTTPS-сервер панели по сохранённым настройкам.
func applyPanelTLS() error {
	cfg := core.LoadPanelTLS()
	panelTLSMu.Lock()
	defer panelTLSMu.Unlock()
	if panelTLSSrv != nil {
		_ = panelTLSSrv.Close()
		panelTLSSrv = nil
	}
	panelCfg.Store(&cfg)
	if cfg.Mode == "off" || cfg.Mode == "" {
		return nil
	}
	if err := core.ConfigureACME(); err != nil && cfg.Mode == "acme" {
		return err
	}
	srv := &http.Server{Addr: ":" + strconv.Itoa(cfg.Port), Handler: panelRoot, ReadHeaderTimeout: 15 * time.Second, DisableGeneralOptionsHandler: true}
	var crt, key string
	switch cfg.Mode {
	case "self":
		host := db.GetSetting("public_host", "localhost")
		p, err := cert.EnsureSelfSigned(host)
		if err != nil {
			return err
		}
		crt, key = p.CertFile, p.KeyFile
	case "custom":
		if _, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile); err != nil {
			return fmt.Errorf("сертификат не загружается: %w", err)
		}
		crt, key = cfg.CertFile, cfg.KeyFile
	case "acme":
		srv.TLSConfig = acme.TLSConfig()
	case "acme-ip":
		// Сертификат на IP: если он уже есть – используем; если нет, пока работает самоподписанный, а настоящий выпускается в фоне.
		if _, _, _, err := ipCertIfValid(cfg); err == nil {
			srv.TLSConfig = acme.IPTLSConfig(cfg.Domain)
		} else {
			host := db.GetSetting("public_host", cfg.Domain)
			p, e := cert.EnsureSelfSigned(host)
			if e != nil {
				return e
			}
			crt, key = p.CertFile, p.KeyFile
			go func() {
				if _, _, _, e := acme.IPFiles(cfg.Domain, cfg.Email); e != nil {
					events.Audit("система", "Сертификат Let's Encrypt на IP не выпущен", e.Error())
					return
				}
				_ = applyPanelTLS()
			}()
		}
	default:
		return fmt.Errorf("неизвестный режим %q", cfg.Mode)
	}
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("порт %d для HTTPS занят: %w", cfg.Port, err)
	}
	panelTLSSrv = srv
	go func() { _ = srv.ServeTLS(ln, crt, key) }() // при заданном TLSConfig с GetCertificate файлы не нужны (crt и key пусты)
	if cfg.Mode == "acme" {                        // сразу просим сертификат, чтобы первый вход не ждал выпуска
		go func() {
			// ошибку выпуска нужно видеть: иначе «HTTPS включён, но сертификата нет» ничем не проявляется
			if _, _, _, err := acme.Files(cfg.Domain); err != nil {
				log.Printf("Let's Encrypt: сертификат для %s не выпущен: %v", cfg.Domain, err)
				events.Audit("система", "Не удалось выпустить сертификат Let's Encrypt для панели", cfg.Domain+": "+err.Error())
			}
		}()
	}
	return nil
}

func handlePanelTLSGet(c *gin.Context) {
	cfg := core.LoadPanelTLS()
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	c.JSON(http.StatusOK, gin.H{"config": cfg, "running": panelTLSSrv != nil, "scheme": scheme})
}

func handlePanelTLSSet(c *gin.Context) {
	var req core.PanelTLS
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}
	switch req.Mode {
	case "off", "self", "acme", "acme-ip", "custom":
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Режим: off, self, acme, acme-ip или custom"})
		return
	}
	if req.Port < 1 || req.Port > 65535 || req.Port == 80 || req.Port == 8080 {
		req.Port = 8443
	}
	req.Domain = strings.ToLower(strings.TrimSpace(req.Domain))
	if req.Mode == "acme" {
		if req.Domain == "" || net.ParseIP(req.Domain) != nil || !strings.Contains(req.Domain, ".") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Для Let's Encrypt укажите домен (не IP-адрес), который смотрит на этот сервер"})
			return
		}
	}
	if req.Mode == "acme-ip" {
		if net.ParseIP(req.Domain) == nil {
			req.Domain = linkHost(c)
		}
		if net.ParseIP(req.Domain) == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Для сертификата на IP откройте панель по IP-адресу сервера"})
			return
		}
	}
	// Проверяем заранее: ответ должен дойти до браузера, а HTTPS-сервер, через который он идёт, перезапустится после него.
	if req.Mode == "custom" {
		if err := validateCustomCert(req.CertFile, req.KeyFile); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Сертификат не подходит: " + err.Error()})
			return
		}
	}
	if req.Mode != "off" {
		panelTLSMu.Lock()
		same := panelTLSSrv != nil && panelTLSSrv.Addr == ":"+strconv.Itoa(req.Port)
		panelTLSMu.Unlock()
		if !same {
			ln, err := net.Listen("tcp", ":"+strconv.Itoa(req.Port))
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Порт %d занят другой программой", req.Port)})
				return
			}
			_ = ln.Close()
		}
	}
	old := core.LoadPanelTLS()
	if err := core.SavePanelTLS(req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		if err := applyPanelTLS(); err != nil {
			_ = core.SavePanelTLS(old)
			_ = applyPanelTLS()
			events.Audit("система", "HTTPS панели не запустился", err.Error())
		}
	}()
	host := linkHost(c)
	if req.Mode == "acme" || req.Mode == "acme-ip" {
		host = req.Domain
	}
	url := ""
	if req.Mode != "off" {
		url = "https://" + net.JoinHostPort(host, strconv.Itoa(req.Port)) + "/"
		// с секретным путём без него новый адрес отвечал бы 404 и выглядел как потеря доступа
		if pp := panelPath(); pp != "" {
			url += pp + "/"
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "Настройки HTTPS применены", "url": url})
}

// ipCertIfValid: есть ли действующий сертификат на IP панели (без попытки выпуска).
func ipCertIfValid(cfg core.PanelTLS) (crt, key string, ok bool, err error) {
	crt, key = acme.IPPaths(cfg.Domain)
	if exp := acme.CertExpiry(crt); exp.IsZero() || time.Until(exp) <= 0 {
		return "", "", false, fmt.Errorf("сертификата на IP нет или он истёк")
	}
	return crt, key, true, nil
}

// refreshPanelIPCert продлевает сертификат на IP, пока он не истёк (вызывается раз в несколько часов).
func refreshPanelIPCert() {
	cfg := core.LoadPanelTLS()
	if cfg.Mode != "acme-ip" {
		return
	}
	if _, _, changed, err := acme.IPFiles(cfg.Domain, cfg.Email); err != nil {
		events.Audit("система", "Не удалось продлить сертификат на IP", err.Error())
	} else if changed {
		events.Audit("система", "Сертификат Let's Encrypt на IP продлён", cfg.Domain)
	}
}
