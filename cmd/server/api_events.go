package main

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/events"
	"kitsune/internal/update"
	"kitsune/internal/version"
)

// Человекочитаемые названия действий для журнала.
var actionTitles = map[string]string{
	"POST /api/v1/admin/password":          "Смена пароля администратора",
	"POST /api/v1/system/fix":              "Автоисправление",
	"POST /api/v1/system/restart-xray":     "Перезапуск ядер",
	"POST /api/v1/system/update-xray":      "Установка ядра Xray",
	"POST /api/v1/system/update/apply":     "Обновление панели",
	"POST /api/v1/system/update-kitsune":   "Обновление панели",
	"PUT /api/v1/cores/settings/:id":       "Настройки ядра",
	"POST /api/v1/cores/:id/install":       "Установка ядра",
	"PUT /api/v1/settings/server":          "Смена адреса сервера",
	"PUT /api/v1/settings/client-routing":  "Маршрутизация клиентов",
	"PUT /api/v1/settings/port-mode":       "Смена режима портов",
	"PUT /api/v1/bridges":                  "Узлы моста (каскад)",
	"PUT /api/v1/settings/telegram":        "Настройка уведомлений",
	"PUT /api/v1/xray/settings":            "Настройки Xray",
	"PUT /api/v1/masking/stub":             "Смена страницы-заглушки",
	"POST /api/v1/masking/sni":             "Смена сайта маскировки",
	"POST /api/v1/masking/scan":            "Поиск сайта маскировки среди соседей по подсети",
	"POST /api/v1/inbounds":                "Создание подключения",
	"POST /api/v1/inbounds/quick-setup":    "Быстрая настройка подключений",
	"PUT /api/v1/inbounds/:id":             "Изменение подключения",
	"DELETE /api/v1/inbounds/:id":          "Удаление подключения",
	"POST /api/v1/users":                   "Создание пользователя",
	"POST /api/v1/users/bulk":              "Массовое действие над пользователями",
	"PUT /api/v1/users/:id":                "Изменение пользователя",
	"DELETE /api/v1/users/:id":             "Удаление пользователя",
	"POST /api/v1/users/:id/toggle":        "Включение/отключение пользователя",
	"POST /api/v1/users/:id/reset-traffic": "Сброс трафика пользователя",
	"POST /api/v1/users/:id/regen-sub":     "Новая ссылка подписки пользователя",
	"POST /api/v1/masking/selfsteal":       "Сайт на своём домене включён",
	"DELETE /api/v1/masking/selfsteal":     "Сайт на своём домене выключен",
	"POST /api/v1/groups":                  "Создание группы",
	"PUT /api/v1/groups/:id":               "Изменение группы",
	"DELETE /api/v1/groups/:id":            "Удаление группы",
	"POST /api/v1/templates":               "Создание шаблона",
	"PUT /api/v1/templates/:id":            "Изменение шаблона",
	"DELETE /api/v1/templates/:id":         "Удаление шаблона",
	"POST /api/v1/backup/restore":          "Восстановление из копии",
	"POST /api/v1/import/run":              "Импорт config.json Xray",
	"GET /api/v1/backup/export":            "Скачивание резервной копии",
	"POST /api/v1/security/totp/enable":    "Включение двухфакторного входа",
	"POST /api/v1/security/totp/disable":   "Отключение двухфакторного входа",
	"POST /api/v1/settings/telegram/test":  "Проверка уведомлений",
	"PUT /api/v1/settings/subscription":    "Настройки подписки",
	"PUT /api/v1/settings/panel-tls":       "Настройки HTTPS панели",
}

// auditMiddleware пишет в журнал каждое изменяющее действие администратора (без тела запроса: там могут быть пароли).
func auditMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		key := c.Request.Method + " " + c.FullPath()
		title, ok := actionTitles[key]
		if !ok {
			return
		}
		actor, _ := sessions.Default(c).Get("username").(string)
		detail := ""
		if id := c.Param("id"); id != "" {
			detail = "#" + id
		}
		if c.Writer.Status() >= 400 {
			detail = strings.TrimSpace(detail + " (ошибка " + strconv.Itoa(c.Writer.Status()) + ")")
		}
		events.Audit(actor, title, detail)
	}
}

func handleAuditGet(c *gin.Context) {
	n, _ := strconv.Atoi(c.Query("limit"))
	c.JSON(http.StatusOK, gin.H{"entries": events.List(n)})
}

func handleTelegramGet(c *gin.Context) {
	t := events.LoadTelegram()
	c.JSON(http.StatusOK, gin.H{"enabled": t.Enabled, "chat_id": t.ChatID, "token_set": t.Token != "", "events": t.Events, "kinds": events.Kinds,
		"bot": t.Bot, "admins": t.Admins})
}

func handleTelegramSet(c *gin.Context) {
	var req struct {
		Token   string   `json:"token"`
		ChatID  string   `json:"chat_id"`
		Enabled bool     `json:"enabled"`
		Events  []string `json:"events"`
		Bot     bool     `json:"bot"`
		Admins  []int64  `json:"admins"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}
	t := events.LoadTelegram()
	if tk := strings.TrimSpace(req.Token); tk != "" {
		if !strings.Contains(tk, ":") || strings.ContainsAny(tk, " /") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Токен бота выглядит как 123456:ABC… (его выдаёт @BotFather)"})
			return
		}
		t.Token = tk
	}
	t.ChatID = strings.TrimSpace(req.ChatID)
	t.Enabled = req.Enabled
	t.Events = req.Events
	if t.Enabled && (t.Token == "" || t.ChatID == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Для уведомлений нужны токен бота и ID чата"})
		return
	}
	admins, err := cleanAdmins(req.Admins)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	t.Bot, t.Admins = req.Bot, admins
	if t.Bot && (t.Token == "" || len(t.Admins) == 0) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Для управления через бота нужны токен и ID хотя бы одного администратора"})
		return
	}
	if err := events.SaveTelegram(t); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Настройки уведомлений сохранены"})
}

// cleanAdmins проверяет список ID администраторов бота: положительные числа, без повторов, не больше десяти.
func cleanAdmins(in []int64) ([]int64, error) {
	var out []int64
	seen := map[int64]bool{}
	for _, id := range in {
		if id <= 0 {
			return nil, fmt.Errorf("ID администратора должен быть положительным числом (свой ID покажет бот @userinfobot)")
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	if len(out) > 10 {
		return nil, fmt.Errorf("администраторов бота не больше десяти")
	}
	return out, nil
}

func handleTelegramTest(c *gin.Context) {
	if err := events.SendTest(); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Сообщение отправлено – проверьте Telegram"})
}

// StartNotifier следит за состоянием и шлёт уведомления: упавшие ядра, истекающие сроки, обновления.
func StartNotifier() {
	time.Sleep(90 * time.Second) // дать ядрам запуститься после старта панели
	lastDaily := time.Time{}
	for range time.Tick(30 * time.Second) {
		for _, comp := range core.Components() {
			key := comp.ID
			if comp.Needed && comp.Installed && !comp.Running {
				events.Notify("core_down", key, fmt.Sprintf("ядро %s не запущено, хотя нужно подключениям", comp.Title), 30*time.Minute)
			} else {
				events.Reset("core_down", key)
			}
		}
		if time.Since(lastDaily) < time.Hour {
			continue
		}
		lastDaily = time.Now()
		now := time.Now().UnixMilli()
		users, _ := db.GetUsers()
		for _, u := range users {
			if u.Active() && u.ExpiryTime > now && u.ExpiryTime < now+3*24*3600*1000 {
				left := int((u.ExpiryTime-now)/(24*3600*1000)) + 1
				events.Notify("user_expiring", fmt.Sprintf("%d|%d", u.ID, u.ExpiryTime), fmt.Sprintf("у пользователя %s срок истекает через %d дн.", u.Name, left), 24*time.Hour)
			}
		}
		if useManifest() {
			if url, key := update.Source(); url != "" {
				if info, err := update.Check(url, version.Version, key); err == nil && info.Available {
					events.Notify("update", info.Latest, "доступна новая версия панели "+info.Latest+" (у вас "+version.Version+")", 24*time.Hour)
				}
			}
		} else {
			// обычный путь – GitHub Latest Release: версию узнаёт updateWatcher, здесь берём его последний ответ
			updMu.Lock()
			info := updCached
			updMu.Unlock()
			if info != nil && info.Available {
				events.Notify("update", info.Latest, "доступна новая версия панели "+info.Latest+" (у вас "+version.Version+")", 24*time.Hour)
			}
		}
		// ядра: новый выпуск Xray, sing-box и других (GitHub опрашивается не чаще раза в 6 часов, ответ кэшируется)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		for _, l := range core.LatestVersions(ctx) {
			if !l.Newer {
				continue
			}
			text := fmt.Sprintf("вышла новая версия ядра %s: %s (у вас %s)", coreTitle(l.ID), l.Latest, l.Pinned)
			if l.Fresh {
				text += "; ей меньше 3 суток, мы её ещё не проверяли"
			}
			events.Notify("core_update", l.ID+"|"+l.Latest, text, 24*time.Hour)
		}
		cancel()
	}
}

// coreTitle – человеческое имя ядра для уведомлений (в списке ядер оно есть у каждого); иначе внутренний идентификатор.
func coreTitle(id string) string {
	for _, c := range core.Components() {
		if c.ID == id {
			return c.Title
		}
	}
	return id
}
