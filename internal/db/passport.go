package db

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// История «Паспорта безопасности»: каждая проверка с оценкой и строками, которые не «в порядке».

type PassportLine struct {
	Level string `json:"level"`
	Text  string `json:"text"`
}

type PassportRecord struct {
	At    int64          `json:"at"` // миллисекунды Unix
	Score int            `json:"score"`
	Bad   int            `json:"bad"`
	Warn  int            `json:"warn"`
	Lines []PassportLine `json:"lines"`
}

const (
	passportKeepDays = 90
	passportMaxRows  = 400
	passportQuiet    = 6 * time.Hour // одинаковый результат чаще, чем раз в это время, не записывается
)

func initPassport() {
	_, _ = DB.Exec(`CREATE TABLE IF NOT EXISTS passport_history (
		at BIGINT PRIMARY KEY,
		score INTEGER NOT NULL,
		bad INTEGER DEFAULT 0,
		warn INTEGER DEFAULT 0,
		lines TEXT DEFAULT '[]'
	)`)
}

func passportSig(lines []PassportLine) string {
	parts := make([]string, len(lines))
	for i, l := range lines {
		parts[i] = l.Level + "|" + l.Text
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}

// AddPassport записывает результат проверки. Если ничего не изменилось с прошлой записи и она свежая, запись пропускается.
func AddPassport(score, bad, warn int, lines []PassportLine) error {
	now := time.Now()
	hist := GetPassport(1)
	if len(hist) == 1 {
		last := hist[0]
		if last.Score == score && passportSig(last.Lines) == passportSig(lines) && now.Sub(time.UnixMilli(last.At)) < passportQuiet {
			return nil
		}
	}
	if lines == nil {
		lines = []PassportLine{}
	}
	b, _ := json.Marshal(lines)
	if _, err := DB.Exec(`INSERT OR REPLACE INTO passport_history (at, score, bad, warn, lines) VALUES (?, ?, ?, ?, ?)`,
		now.UnixMilli(), score, bad, warn, string(b)); err != nil {
		return err
	}
	_, _ = DB.Exec(`DELETE FROM passport_history WHERE at < ?`, now.AddDate(0, 0, -passportKeepDays).UnixMilli())
	_, _ = DB.Exec(`DELETE FROM passport_history WHERE at NOT IN (SELECT at FROM passport_history ORDER BY at DESC LIMIT ?)`, passportMaxRows)
	return nil
}

// GetPassport отдаёт последние записи, старые первыми.
func GetPassport(limit int) []PassportRecord {
	out := []PassportRecord{}
	rows, err := DB.Query(`SELECT at, score, bad, warn, lines FROM passport_history ORDER BY at DESC LIMIT ?`, limit)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var r PassportRecord
		var raw string
		if rows.Scan(&r.At, &r.Score, &r.Bad, &r.Warn, &raw) != nil {
			continue
		}
		if json.Unmarshal([]byte(raw), &r.Lines) != nil || r.Lines == nil {
			r.Lines = []PassportLine{}
		}
		out = append(out, r)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
