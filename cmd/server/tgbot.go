package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/events"
	"kitsune/internal/tgbot"
	"kitsune/internal/version"
)

// startTelegramBot запускает админ-бота. Настройки читаются заново на каждом шаге опроса, поэтому включение и смена токена или списка
// администраторов в панели действуют без перезапуска.
func startTelegramBot(ctx context.Context) {
	b := &tgbot.Bot{
		Config: func() tgbot.Config {
			t := events.LoadTelegram()
			return tgbot.Config{Token: t.Token, Admins: t.Admins, Enabled: t.Bot}
		},
		Backend: botBackend{},
		API:     func() string { return events.TelegramAPI },
		Audit:   events.Audit,
	}
	b.Run(ctx)
}

// rememberSubBase запоминает адрес, по которому администратор открывает панель: бот строит из него ссылки подписки.
// Локальные адреса (SSH-туннель) не запоминаются: такая ссылка клиентам не нужна.
func rememberSubBase(c *gin.Context) {
	if h := linkHost(c); h == "" || isLoopback(h) || !validHostName(h) {
		return
	}
	if base := subBase(c); db.GetSetting("sub_base", "") != base {
		_ = db.SetSetting("sub_base", base)
	}
}

// botSubBase – адрес для ссылок подписки без запроса: запомненный, иначе адрес сервера и порт панели.
func botSubBase() string {
	base := strings.TrimRight(db.GetSetting("sub_base", ""), "/")
	if base == "" {
		host := db.GetSetting("public_host", "")
		if host == "" {
			return ""
		}
		base = "http://" + net.JoinHostPort(host, strconv.Itoa(panelPort()))
	}
	if cfg := panelCfg.Load(); cfg != nil && cfg.Mode != "" && cfg.Mode != "off" {
		if host, ok := strings.CutPrefix(base, "http://"); ok {
			return panelHTTPSBase(cfg, host)
		}
	}
	return base
}

type botBackend struct{}

func toBotUser(u db.User) tgbot.User {
	return tgbot.User{ID: u.ID, Name: u.Name, Enabled: u.Enable, Active: u.Active(), Used: u.UsedTraffic, Limit: u.TrafficLimit, ExpiryMs: u.ExpiryTime}
}

func (botBackend) Status() string {
	var sb strings.Builder
	sb.WriteString("Kitsune " + version.Version + "\n")
	var cores []string
	for _, c := range core.Components() {
		if !c.Needed && !c.Running {
			continue
		}
		mark := "✅"
		if !c.Running {
			mark = "❌"
		}
		cores = append(cores, c.Title+" "+mark)
	}
	if len(cores) == 0 {
		cores = []string{"нет запущенных"}
	}
	sb.WriteString("Ядра: " + strings.Join(cores, ", ") + "\n")
	inbounds, _ := db.GetInbounds()
	on := 0
	for _, ib := range inbounds {
		if ib.Enable {
			on++
		}
	}
	users, _ := db.GetUsers()
	active := 0
	for _, u := range users {
		if u.Active() {
			active++
		}
	}
	fmt.Fprintf(&sb, "Подключений включено: %d из %d\nПользователей: активных %d из %d", on, len(inbounds), active, len(users))
	return sb.String()
}

func (botBackend) Users() []tgbot.User {
	us, _ := db.GetUsers()
	out := make([]tgbot.User, 0, len(us))
	for _, u := range us {
		out = append(out, toBotUser(u))
	}
	return out
}

func (botBackend) Find(name string) (tgbot.User, bool) {
	name = strings.TrimSpace(name)
	us, _ := db.GetUsers()
	clean := db.CleanName(name)
	for _, u := range us {
		if strings.EqualFold(u.Name, name) || (clean != "" && strings.EqualFold(u.Name, clean)) {
			return toBotUser(u), true
		}
	}
	return tgbot.User{}, false
}

func (botBackend) ByID(id int) (tgbot.User, bool) {
	u, err := db.GetUser(id)
	if err != nil {
		return tgbot.User{}, false
	}
	return toBotUser(*u), true
}

// Create делает то же, что кнопка «Добавить пользователя» в панели (без шаблона и группы).
func (b botBackend) Create(name string, days, gb int) (tgbot.User, error) {
	if clean := db.CleanName(name); clean == "" {
		return tgbot.User{}, errors.New("в имени нужны буквы или цифры")
	} else if _, exists := b.Find(clean); exists {
		return tgbot.User{}, errors.New("пользователь «" + clean + "» уже есть")
	}
	var expiry int64
	if days > 0 {
		expiry = db.NowPlusDays(days)
	}
	u, err := db.CreateUser(name, int64(gb)<<30, expiry, 0)
	if err != nil {
		return tgbot.User{}, errors.New("не удалось создать пользователя")
	}
	markKnownActive(u.ID)
	botApply()
	nu, _ := db.GetUser(u.ID)
	if nu == nil {
		nu = u
	}
	return toBotUser(*nu), nil
}

// Extend прибавляет дни к текущему сроку (если он ещё не истёк) или считает от сегодня.
func (botBackend) Extend(id, days int) (tgbot.User, error) {
	u, err := db.GetUser(id)
	if err != nil {
		return tgbot.User{}, errors.New("пользователь не найден")
	}
	base := time.Now().UnixMilli()
	if u.ExpiryTime > base {
		base = u.ExpiryTime
	}
	ms := base + int64(days)*24*3600*1000
	if err := db.UpdateUser(id, db.UserPatch{ExpiryTime: &ms}); err != nil {
		return tgbot.User{}, err
	}
	botApply()
	nu, _ := db.GetUser(id)
	return toBotUser(*nu), nil
}

func (botBackend) SetEnabled(id int, on bool) (tgbot.User, error) {
	if _, err := db.GetUser(id); err != nil {
		return tgbot.User{}, errors.New("пользователь не найден")
	}
	if err := db.UpdateUser(id, db.UserPatch{Enable: &on}); err != nil {
		return tgbot.User{}, err
	}
	botApply()
	nu, _ := db.GetUser(id)
	return toBotUser(*nu), nil
}

// Delete удаляет пользователя так же, как кнопка в панели: запись в базе и пересборка ядер.
func (botBackend) Delete(id int) error {
	if _, err := db.GetUser(id); err != nil {
		return errors.New("пользователь не найден")
	}
	if err := db.DeleteUser(id); err != nil {
		return errors.New("ошибка удаления")
	}
	botApply()
	return nil
}

func (botBackend) Link(id int) (string, error) {
	u, err := db.GetUser(id)
	if err != nil {
		return "", errors.New("пользователь не найден")
	}
	base := botSubBase()
	if base == "" {
		return "", errors.New("Я ещё не знаю адрес панели. Откройте в панели ссылки любого пользователя (значок QR) один раз, и я запомню его")
	}
	return base + "/sub/" + u.SubID, nil
}

// botApply применяет изменения к ядрам; ошибка ядра не отменяет уже записанное (как и в интерфейсе панели).
func botApply() {
	if err := applyCores(); err != nil {
		events.Audit("Telegram", "Ядро не приняло конфиг", err.Error())
	}
}
