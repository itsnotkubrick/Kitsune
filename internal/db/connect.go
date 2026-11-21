package db

import "time"

// Этапы подключения человека по странице «Подключить за пару минут»: что он уже сделал.
const (
	EvPage  = "page"  // открыл страницу
	EvStore = "store" // нажал «Скачать» приложение
	EvAdd   = "add"   // нажал «Добавить в приложение»
	EvSub   = "sub"   // приложение получило подписку
)

// ConnectEvent – последнее срабатывание этапа.
type ConnectEvent struct {
	At    int64  `json:"at"` // миллисекунды Unix
	Count int    `json:"count"`
	Extra string `json:"extra"` // платформа или название приложения
}

func initConnect() {
	_, _ = DB.Exec(`CREATE TABLE IF NOT EXISTS connect_events (
		user_id INTEGER NOT NULL,
		event TEXT NOT NULL,
		at BIGINT DEFAULT 0,
		count INTEGER DEFAULT 0,
		extra TEXT DEFAULT '',
		PRIMARY KEY (user_id, event)
	)`)
}

// MarkConnect запоминает этап: время последнего срабатывания, число раз и пометку (платформа, приложение).
func MarkConnect(userID int, event, extra string) error {
	_, err := DB.Exec(`INSERT INTO connect_events (user_id, event, at, count, extra) VALUES (?, ?, ?, 1, ?)
		ON CONFLICT(user_id, event) DO UPDATE SET at = excluded.at, count = count + 1,
		extra = CASE WHEN excluded.extra = '' THEN extra ELSE excluded.extra END`,
		userID, event, time.Now().UnixMilli(), CleanHeader(extra, 40))
	return err
}

// GetConnect отдаёт этапы пользователя по названию.
func GetConnect(userID int) map[string]ConnectEvent {
	out := map[string]ConnectEvent{}
	rows, err := DB.Query("SELECT event, at, count, extra FROM connect_events WHERE user_id = ?", userID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var ev string
		var e ConnectEvent
		if rows.Scan(&ev, &e.At, &e.Count, &e.Extra) == nil {
			out[ev] = e
		}
	}
	return out
}
