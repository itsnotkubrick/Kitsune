package db

import (
	"errors"
	"strings"
	"time"
)

// Проверка стабильности соединения: одноразовые ссылки и результаты, которые присылает страница проверки из сети человека.

type StabilityResult struct {
	ID    int64  `json:"id"`
	At    int64  `json:"at"`   // миллисекунды Unix
	Kind  string `json:"kind"` // mobile | home | other
	Note  string `json:"note"` // оператор или пометка человека
	OK    bool   `json:"ok"`
	Bytes int    `json:"bytes"` // сколько байт пришло до остановки
	MS    int    `json:"ms"`
}

const (
	stabilityLinkDays   = 14
	stabilityKeepDays   = 90
	stabilityPerLinkMax = 200
)

func initStability() {
	// переименование таблиц старых версий
	_, _ = DB.Exec(`ALTER TABLE freeze_links RENAME TO stability_links`)
	_, _ = DB.Exec(`ALTER TABLE freeze_results RENAME TO stability_results`)
	_, _ = DB.Exec(`CREATE TABLE IF NOT EXISTS stability_links (token TEXT PRIMARY KEY, created BIGINT NOT NULL)`)
	_, _ = DB.Exec(`CREATE TABLE IF NOT EXISTS stability_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL, at BIGINT NOT NULL,
		kind TEXT DEFAULT 'other', note TEXT DEFAULT '', ok INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0, ms INTEGER DEFAULT 0)`)
}

// NewStabilityLink создаёт ссылку для проверки (действует 14 дней, ею можно проверить несколько сетей).
func NewStabilityLink() (string, error) {
	tok := RandomSlug(24)
	now := time.Now()
	if _, err := DB.Exec(`INSERT INTO stability_links (token, created) VALUES (?, ?)`, tok, now.UnixMilli()); err != nil {
		return "", err
	}
	_, _ = DB.Exec(`DELETE FROM stability_links WHERE created < ?`, now.AddDate(0, 0, -stabilityLinkDays).UnixMilli())
	_, _ = DB.Exec(`DELETE FROM stability_results WHERE at < ?`, now.AddDate(0, 0, -stabilityKeepDays).UnixMilli())
	return tok, nil
}

func StabilityLinkValid(token string) bool {
	var n int
	return DB.QueryRow(`SELECT COUNT(*) FROM stability_links WHERE token = ? AND created >= ?`, token,
		time.Now().AddDate(0, 0, -stabilityLinkDays).UnixMilli()).Scan(&n) == nil && n > 0
}

// AddStabilityResult записывает результат проверки. Ввод чистится и ограничивается.
func AddStabilityResult(token, kind, note string, ok bool, bytes, ms int) error {
	if !StabilityLinkValid(token) {
		return errors.New("ссылка не найдена")
	}
	if kind != "mobile" && kind != "home" {
		kind = "other"
	}
	if bytes < 0 {
		bytes = 0
	}
	if ms < 0 {
		ms = 0
	}
	var n int
	_ = DB.QueryRow(`SELECT COUNT(*) FROM stability_results WHERE token = ?`, token).Scan(&n)
	if n >= stabilityPerLinkMax {
		return errors.New("слишком много результатов для этой ссылки")
	}
	okInt := 0
	if ok {
		okInt = 1
	}
	_, err := DB.Exec(`INSERT INTO stability_results (token, at, kind, note, ok, bytes, ms) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		token, time.Now().UnixMilli(), kind, cleanNote(note, 40), okInt, bytes, ms)
	return err
}

// GetStabilityResults отдаёт последние результаты, свежие первыми.
func GetStabilityResults(limit int) []StabilityResult {
	out := []StabilityResult{}
	rows, err := DB.Query(`SELECT id, at, kind, note, ok, bytes, ms FROM stability_results ORDER BY at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var r StabilityResult
		var ok int
		if rows.Scan(&r.ID, &r.At, &r.Kind, &r.Note, &ok, &r.Bytes, &r.MS) == nil {
			r.OK = ok == 1
			out = append(out, r)
		}
	}
	return out
}

// StabilitySummary считает результаты за последние days дней: сколько всего, сколько показали остановку передачи и последний результат.
func StabilitySummary(days int) (total, stalled int, last StabilityResult) {
	since := time.Now().AddDate(0, 0, -days).UnixMilli()
	for i, r := range GetStabilityResults(200) {
		if r.At < since {
			continue
		}
		if i == 0 || last.At == 0 {
			last = r
		}
		total++
		if !r.OK {
			stalled++
		}
	}
	return
}

// cleanNote оставляет в пометке человека читаемый текст (в том числе кириллицу): без управляющих символов, угловых скобок и лишней длины.
func cleanNote(s string, max int) string {
	out := make([]rune, 0, max)
	for _, r := range strings.TrimSpace(s) {
		if r < 32 || r == 127 || r == '<' || r == '>' || r == '"' || r == '\\' {
			continue
		}
		out = append(out, r)
		if len(out) >= max {
			break
		}
	}
	return strings.TrimSpace(string(out))
}
