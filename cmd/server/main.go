package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"

	"kitsune/internal/cert"
	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/events"
	"kitsune/internal/importer"
	"kitsune/internal/metrics"
	"kitsune/internal/security"
	"kitsune/internal/selfsteal"
	"kitsune/internal/site"
	"kitsune/internal/version"
	"kitsune/web"
)

func main() {
	if runCLI(os.Args[1:]) {
		return
	}
	log.Println("Запуск Kitsune...")

	db.InitDB()
	importer.CleanTemp() // остатки прерванных загрузок импорта
	events.Init()
	migrateLegacyInbounds()
	_ = db.SyncMembership()
	metrics.Start()
	initStub()        // заглушка выбирается до запуска ядер: Hysteria и сайт на домене берут одну и ту же страницу
	site.StartLocal() // слушатель ответов постороннему должен открыться до сборки конфига Hysteria (её соберёт StartAll)
	go core.StartAll()
	go StartTrafficMonitor()
	go StartNotifier()
	go certMaintenance()
	go core.LogMaintenance()
	go updateWatcher()
	go passportLoop()
	go bridgeMonitor()
	go startTelegramBot(context.Background())
	selfsteal.Apply()

	if os.Getenv("KITSUNE_DEBUG") == "" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New() // не gin.Default(): его журнал пишет адрес целиком, а в адресе подписки лежит ключ доступа
	r.Use(accessLogger(gin.DefaultWriter), gin.CustomRecoveryWithWriter(nil, func(c *gin.Context, _ any) {
		log.Printf("Паника в HTTP-обработчике %q\n%s", c.FullPath(), debug.Stack())
		c.AbortWithStatus(http.StatusInternalServerError)
	}))
	// X-Forwarded-For не верим никому, кроме явно заданных прокси: иначе IP (лимит входа, журнал) подделывается.
	if err := r.SetTrustedProxies(trustedProxiesFromEnv()); err != nil {
		log.Fatalf("Доверенные прокси заданы неверно: %v", err)
	}

	store := cookie.NewStore(sessionSecret())
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   int(sessionMaxAge / time.Second),
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
	r.Use(frameHeaders())
	r.Use(sessions.Sessions(sessionCookie, store))
	r.Use(gateMiddleware())
	r.Use(bodyLimit())
	r.Use(csrfGuard())
	setupNotFound(r)

	r.GET("/", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", web.IndexHTML)
	})
	r.GET("/logo.png", func(c *gin.Context) {
		c.Data(http.StatusOK, "image/png", web.LogoPNG)
	})
	r.GET("/logo_text.png", func(c *gin.Context) {
		c.Data(http.StatusOK, "image/png", web.LogoTextPNG)
	})
	r.GET("/tools/*filepath", AuthRequired(), handleTools)
	r.GET("/static/*filepath", handleStatic)

	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "app": "Kitsune", "version": version.Version})
	})

	r.GET("/sub/:subid", handleSubscription)
	r.HEAD("/sub/:subid", handleSubscription)
	r.GET("/sub/stability/:token", handleStabilityPage)
	r.GET("/sub/stability/:token/blob", handleStabilityBlob)
	r.POST("/sub/stability/:token/result", handleStabilityResult)
	r.GET("/sub/:subid/connect", handleConnectPage)
	r.POST("/sub/:subid/connect/e/:event", handleConnectEvent)
	r.POST("/api/v1/login", noStore(), handleLogin)
	r.POST("/api/v1/logout", noStore(), handleLogout)

	api := r.Group("/api/v1")
	api.Use(noStore())
	api.Use(AuthRequired())
	api.Use(auditMiddleware())
	{
		api.POST("/admin/password", handleChangePassword)
		api.GET("/security/totp", handleTOTPStatus)
		api.POST("/security/totp/setup", handleTOTPSetup)
		api.POST("/security/totp/enable", handleTOTPEnable)
		api.POST("/security/totp/disable", handleTOTPDisable)

		registerPro(api)

		// Система
		api.GET("/system/status", handleSystemStatus)
		api.GET("/system/metrics", handleMetrics)
		api.GET("/system/check", handleCheck)
		api.GET("/system/report", handleSupportReport)
		api.GET("/system/passport/history", handlePassportHistory)
		api.POST("/system/stability/new", handleStabilityNew)
		api.GET("/system/stability", handleStabilityList)
		api.PUT("/system/stability/udp-first", handleStabilityUDPFirst)
		api.POST("/system/check/start", handleHealthStart)
		api.GET("/system/check/job", handleHealthJob)
		api.POST("/system/fix", handleFix)
		api.POST("/system/restart-xray", handleRestartXray)
		api.POST("/system/update-xray", handleInstallXray)
		api.GET("/cores", handleCores)
		api.GET("/cores/latest", handleCoresLatest)
		api.GET("/cores/settings", handleCoreSettingsGet)
		api.PUT("/cores/settings/:id", handleCoreSettingsSet)
		api.POST("/cores/:id/install", handleInstallCore)
		api.GET("/system/update/check", handleUpdateCheck)
		api.GET("/system/update/status", handleUpdateStatus)
		api.POST("/system/update/apply", handleUpdateApply)
		api.POST("/system/update-kitsune", handleUpdateApply)
		api.GET("/backup/export", handleExportBackup)
		api.POST("/backup/export", handleExportBackup)
		api.POST("/backup/restore", handleRestoreBackup)
		api.POST("/import/preview", handleImport(false))
		api.POST("/import/run", handleImport(true))
		api.GET("/settings/subscription", handleSubSettingsGet)
		api.PUT("/settings/subscription", handleSubSettingsSet)
		api.GET("/settings/client-routing", handleClientRoutingGet)
		api.PUT("/settings/client-routing", handleClientRoutingSet)
		api.GET("/settings/port-mode", handlePortModeGet)
		api.PUT("/settings/port-mode", handlePortModeSet)
		registerBridgeRoutes(api)
		api.GET("/masking", handleMaskingGet)
		api.PUT("/masking/stub", handleStubSet)
		api.POST("/masking/stub/random", handleStubRandom)
		api.GET("/masking/stub/page", handleStubPage)
		api.GET("/masking/custom", handleStubCustomGet)
		api.PUT("/masking/custom", handleStubCustomSet)
		api.DELETE("/masking/custom", handleStubCustomDelete)
		api.POST("/masking/scan", handleMaskingScan)
		api.POST("/masking/sni", handleMaskingSNI)
		api.GET("/masking/selfsteal", handleSelfStealGet)
		api.POST("/masking/selfsteal", handleSelfStealSet)
		api.DELETE("/masking/selfsteal", handleSelfStealOff)
		api.GET("/settings/panel-tls", handlePanelTLSGet)
		api.PUT("/settings/panel-tls", handlePanelTLSSet)
		api.GET("/settings/server", handleServerSettingsGet)
		api.PUT("/settings/server", handleServerSettingsSet)

		// Ядро Xray: глобальные настройки
		api.GET("/xray/settings", handleXraySettingsGet)
		api.PUT("/xray/settings", handleXraySettingsSet)
		api.GET("/xray/config", handleXrayConfigPreview)

		// Подключения (шлюзы)
		api.GET("/protocols", handleProtocols)
		api.GET("/inbounds", handleGetInbounds)
		api.POST("/inbounds", handleAddInbound)
		api.POST("/inbounds/quick-setup", handleQuickSetup)
		api.PUT("/inbounds/:id", handleUpdateInbound)
		api.DELETE("/inbounds/:id", handleDeleteInbound)

		// Пользователи
		api.GET("/users", handleGetUsers)
		api.POST("/users", handleAddUser)
		api.POST("/users/bulk", handleBulkUsers)
		api.PUT("/users/:id", handleUpdateUser)
		api.DELETE("/users/:id", handleDeleteUser)
		api.POST("/users/:id/toggle", handleToggleUser)
		api.POST("/users/:id/reset-traffic", handleResetUserTraffic)
		api.POST("/users/:id/regen-sub", handleRegenSub)
		api.GET("/users/:id/links", handleUserLinks)
		api.GET("/users/:id/devices", handleUserDevices)
		api.DELETE("/users/:id/devices/:did", handleDeleteUserDevice)
		api.GET("/users/:id/awg/:inbound", handleAWGConfig)

		// Группы доступа и шаблоны пользователей
		api.GET("/audit", handleAuditGet)
		api.GET("/settings/telegram", handleTelegramGet)
		api.PUT("/settings/telegram", handleTelegramSet)
		api.POST("/settings/telegram/test", handleTelegramTest)
		api.GET("/groups", handleGroupsGet)
		api.POST("/groups", handleGroupSave)
		api.PUT("/groups/:id", handleGroupSave)
		api.DELETE("/groups/:id", handleGroupDelete)
		api.POST("/templates", handleTemplateSave)
		api.PUT("/templates/:id", handleTemplateSave)
		api.DELETE("/templates/:id", handleTemplateDelete)
	}

	// Остановка панели (Ctrl+C, systemd stop) останавливает и ядра: иначе они держали бы порты.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		core.StopAll()
		os.Exit(0)
	}()

	addr := os.Getenv("KITSUNE_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	var public http.Handler = r
	if panelPrivate() {
		// Панель только через SSH-туннель: интерфейс слушает 127.0.0.1, а на публичных портах остаются одни подписки.
		public = subOnly(r)
		go func() {
			a := &http.Server{Addr: adminLoopback, Handler: r, ReadHeaderTimeout: 15 * time.Second, DisableGeneralOptionsHandler: true}
			if err := a.ListenAndServe(); err != nil {
				log.Printf("Внутренний адрес панели не запущен: %v", err)
			}
		}()
		log.Printf("Панель доступна только через SSH-туннель (%s); снаружи открыты только подписки", adminLoopback)
	}
	panelRoot = public
	if err := applyPanelTLS(); err != nil {
		log.Printf("HTTPS панели не запущен: %v", err)
	}
	log.Printf("Kitsune запущена на %s", addr)
	srv := &http.Server{Addr: addr, Handler: plainHandler(public), ReadHeaderTimeout: 15 * time.Second, DisableGeneralOptionsHandler: true}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Ошибка запуска сервера: %v", err)
	}
}

// handleStatic отдаёт CSS и скрипты интерфейса. Секретов в них нет, поэтому доступ открыт (нужен и странице входа).
func handleStatic(c *gin.Context) {
	sub, err := fs.Sub(web.StaticFS, "static")
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Header("Cache-Control", "no-cache")
	c.Request.URL.Path = c.Param("filepath")
	http.FileServer(http.FS(sub)).ServeHTTP(c.Writer, c.Request)
}

func handleTools(c *gin.Context) {
	sub, err := fs.Sub(web.ToolsFS, "tools")
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Request.URL.Path = c.Param("filepath")
	http.FileServer(http.FS(sub)).ServeHTTP(c.Writer, c.Request)
}

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get("username")
		if user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Требуется авторизация"})
			return
		}
		if !checkSession(c, session) {
			c.Header("Cache-Control", "no-store")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Сессия истекла, войдите снова", "session_expired": true})
			return
		}
		c.Next()
	}
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Code     string `json:"code"` // одноразовый код, если включён двухфакторный вход
}

func handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}

	ip := c.ClientIP()
	slot, verdict := loginEnter(ip) // проверки с одного адреса идут по одной, иначе параллельный перебор обходит лимит
	if verdict != loginAllowed {
		if verdict == loginBlocked && loginNoticeDue(ip) {
			events.Notify("login", ip, "много неудачных попыток входа с адреса "+ip+": вход закрыт на 10 минут", 30*time.Minute)
		}
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Слишком много неудачных попыток входа. Подождите 10 минут."})
		return
	}
	defer slot.done()
	if db.CheckAdminAuth(req.Username, req.Password) {
		if db.GetSetting("totp_enabled", "") == "1" {
			if strings.TrimSpace(req.Code) == "" { // пароль верный, код ещё не вводили – это не неудача
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Введите код из приложения-аутентификатора", "needs_totp": true})
				return
			}
			ok, limited := totpCheck(req.Code)
			if limited {
				totpLimitedNotice(req.Username, ip)
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "Слишком много неверных кодов. Подождите 10 минут.", "needs_totp": true})
				return
			}
			if !ok { // неверный или уже использованный код: попытка засчитывается
				slot.fail()
				events.Audit(req.Username, "Неверный код двухфакторного входа", ip)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный или уже использованный код", "needs_totp": true})
				return
			}
		}
		slot.success()
		events.Audit(req.Username, "Вход в панель", ip)
		secure := isSecureRequest(c)
		startSession(sessions.Default(c), req.Username, secure)
		c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "Успешная авторизация"})
		return
	}

	slot.fail()
	events.Audit(req.Username, "Неудачная попытка входа", ip)
	c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный логин или пароль"})
}

func handleLogout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	_ = session.Save()
	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "Сессия завершена"})
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func handleChangePassword(c *gin.Context) {
	session := sessions.Default(c)
	val := session.Get("username")
	if val == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Не авторизован"})
		return
	}
	username := val.(string)

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil || len([]rune(req.NewPassword)) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Пароль должен содержать не менее 8 символов"})
		return
	}

	if !db.CheckAdminAuth(username, req.OldPassword) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Неверный текущий пароль"})
		return
	}
	// Пароль не должен быть из известных утечек (проверка по k-anonymity: наружу уходят 5 символов хеша).
	if n, err := security.Pwned(req.NewPassword); err == nil && n > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Этот пароль встречается в утечках (%d раз) – выберите другой", n)})
		return
	}

	if err := db.UpdateAdminCredentials(username, req.NewPassword); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения пароля"})
		return
	}
	startSession(session, username, isSecureRequest(c)) // текущий вход остаётся: прежние куки уже недействительны

	c.JSON(http.StatusOK, gin.H{"message": "Пароль успешно обновлен"})
}

func sessionSecret() []byte {
	if v := db.GetSetting("session_secret", ""); len(v) >= 32 {
		return []byte(v)
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	v := hex.EncodeToString(b)
	_ = db.SetSetting("session_secret", v)
	return []byte(v)
}

// certMaintenance раз в сутки перевыпускает самоподписанный сертификат, когда до конца срока меньше 30 дней.
func certMaintenance() {
	for range time.Tick(6 * time.Hour) {
		refreshPanelIPCert()
		if core.RefreshACME() || cert.NeedsRenewal() {
			_ = applyCores() // сборка конфигов выпустит новый сертификат, ядра перезапустятся с ним
		}
	}
}

// noStore запрещает кеширование ответов API: в них бывают ключи и ссылки.
func noStore() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.Next()
	}
}
