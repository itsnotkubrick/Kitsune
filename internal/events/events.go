// Package events – журнал действий администратора и уведомления в Telegram.
package events

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"kitsune/internal/db"
)

// TelegramAPI – базовый адрес Bot API (подменяется в тестах).
var TelegramAPI = "https://api.telegram.org"

type Entry struct {
	ID     int    `json:"id"`
	Time   int64  `json:"time"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Detail string `json:"detail"`
}

func Init() {
	if v := os.Getenv("KITSUNE_TELEGRAM_API"); v != "" { // для тестов: свой сервер вместо api.telegram.org
		TelegramAPI = v
	}
	_, _ = db.DB.Exec(`CREATE TABLE IF NOT EXISTS audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts BIGINT NOT NULL,
		actor TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL,
		detail TEXT NOT NULL DEFAULT ''
	)`)
	_, _ = db.DB.Exec(`CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts)`)
}

const maxAudit = 5000

// Audit добавляет запись в журнал; старые записи за пределом лимита удаляются.
func Audit(actor, action, detail string) {
	if db.DB == nil {
		return
	}
	_, _ = db.DB.Exec("INSERT INTO audit (ts, actor, action, detail) VALUES (?, ?, ?, ?)", time.Now().Unix(), actor, action, detail)
	_, _ = db.DB.Exec("DELETE FROM audit WHERE id <= (SELECT MAX(id) FROM audit) - ?", maxAudit)
}

func List(limit int) []Entry {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := db.DB.Query("SELECT id, ts, actor, action, detail FROM audit ORDER BY id DESC LIMIT ?", limit)
	out := []Entry{}
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var e Entry
		if rows.Scan(&e.ID, &e.Time, &e.Actor, &e.Action, &e.Detail) == nil {
			out = append(out, e)
		}
	}
	return out
}

// ---- Telegram ----

type Telegram struct {
	Token   string   `json:"token"`
	ChatID  string   `json:"chat_id"`
	Enabled bool     `json:"enabled"`
	Events  []string `json:"events"` // какие события присылать; пусто – все
	// Админ-бот: тот же токен, но свой переключатель и свой список администраторов (числовые ID пользователей Telegram).
	// Пустой список – бот молчит: чужим он не отвечает никогда.
	Bot    bool    `json:"bot,omitempty"`
	Admins []int64 `json:"admins,omitempty"`
}

// Известные виды событий (ключи для настройки уведомлений).
var Kinds = []struct{ Key, Label string }{
	{"core_down", "Ядро (Xray, sing-box…) не запущено"},
	{"user_limit", "Пользователь отключён: лимит трафика или срок"},
	{"user_expiring", "Срок пользователя истекает в ближайшие 3 дня"},
	{"device_limit", "Превышен лимит устройств"},
	{"login", "Блокировка входа после неудачных попыток"},
	{"update", "Доступна новая версия панели"},
	{"core_update", "Вышла новая версия ядра (Xray, sing-box…)"},
	{"bridge_down", "Узел-мост не отвечает"},
}

func LoadTelegram() Telegram {
	t := Telegram{}
	if raw := db.GetSetting("telegram", ""); raw != "" {
		_ = json.Unmarshal([]byte(raw), &t)
	}
	return t
}

func SaveTelegram(t Telegram) error {
	b, _ := json.Marshal(t)
	return db.SetSetting("telegram", string(b))
}

func (t Telegram) wants(kind string) bool {
	if len(t.Events) == 0 {
		return true
	}
	for _, e := range t.Events {
		if e == kind {
			return true
		}
	}
	return false
}

var (
	mu     sync.Mutex
	recent = map[string]time.Time{}
)

// Notify отправляет сообщение в Telegram. Одинаковое событие (kind+key) повторно не шлётся в течение suppress.
func Notify(kind, key, text string, suppress time.Duration) {
	t := LoadTelegram()
	Audit("система", "уведомление", text)
	if !t.Enabled || t.Token == "" || t.ChatID == "" || !t.wants(kind) {
		return
	}
	id := kind + "|" + key
	mu.Lock()
	if last, ok := recent[id]; ok && time.Since(last) < suppress {
		mu.Unlock()
		return
	}
	recent[id] = time.Now()
	mu.Unlock()
	go func() { _ = send(t, text) }()
}

// Reset забывает отправленные события (например, после устранения проблемы повторное возникновение снова уведомит).
func Reset(kind, key string) {
	mu.Lock()
	delete(recent, kind+"|"+key)
	mu.Unlock()
}

func send(t Telegram, text string) error {
	body, _ := json.Marshal(map[string]any{"chat_id": t.ChatID, "text": "Kitsune: " + text, "disable_web_page_preview": true})
	url := fmt.Sprintf("%s/bot%s/sendMessage", strings.TrimRight(TelegramAPI, "/"), t.Token)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		// токен в тексте ошибки не показываем
		return fmt.Errorf("не удалось связаться с Telegram")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Description string `json:"description"`
		}
		_ = json.Unmarshal(b, &e)
		return fmt.Errorf("Telegram ответил %d: %s", resp.StatusCode, e.Description)
	}
	return nil
}

// SendTest отправляет проверочное сообщение синхронно и возвращает ошибку.
func SendTest() error {
	t := LoadTelegram()
	if t.Token == "" || t.ChatID == "" {
		return fmt.Errorf("укажите токен бота и ID чата")
	}
	return send(t, "проверка уведомлений – всё работает")
}
