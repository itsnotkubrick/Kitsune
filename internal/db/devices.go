package db

import (
	"strings"
	"time"
)

// Device – устройство пользователя, которое само назвалось при загрузке подписки (HWID: Happ, INCY и похожие).
type Device struct {
	ID        int64  `json:"id"`
	HWID      string `json:"hwid"`
	OS        string `json:"os"`
	OSVersion string `json:"os_version"`
	Model     string `json:"model"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
}

func initDevices() {
	_, _ = DB.Exec(`CREATE TABLE IF NOT EXISTS user_devices (
		user_id INTEGER NOT NULL,
		hwid TEXT NOT NULL,
		os TEXT DEFAULT '',
		os_version TEXT DEFAULT '',
		model TEXT DEFAULT '',
		first_seen BIGINT DEFAULT 0,
		last_seen BIGINT DEFAULT 0,
		PRIMARY KEY (user_id, hwid)
	)`)
}

// CleanHeader оставляет печатные ASCII-символы (заголовки устройства приходят из сети) и режет по длине.
func CleanHeader(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		}
		if b.Len() >= max {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// MaxUserDevices – потолок устройств на одного пользователя: при превышении вытесняются самые давние.
const MaxUserDevices = 64

// TouchDevice регистрирует обращение устройства. Известное обновляется всегда (пустые ОС и модель
// старые данные не затирают); новое принимается, пока их меньше лимита. Лимит <= 0 или больше
// MaxUserDevices означает потолок MaxUserDevices с вытеснением самых давних. Проверка лимита и вставка
// идут одним запросом, поэтому параллельные новые устройства лимит не обходят.
// Возвращает false, если лимит устройств исчерпан.
func TouchDevice(userID int, d Device, limit int) (bool, error) {
	hwid := strings.ToLower(d.HWID)
	now := time.Now().UnixMilli()
	touch := func() (bool, error) {
		res, err := DB.Exec(`UPDATE user_devices SET last_seen = ?,
			os = COALESCE(NULLIF(?, ''), os), os_version = COALESCE(NULLIF(?, ''), os_version), model = COALESCE(NULLIF(?, ''), model)
			WHERE user_id = ? AND lower(hwid) = ?`, now, d.OS, d.OSVersion, d.Model, userID, hwid)
		if err != nil {
			return false, err
		}
		n, _ := res.RowsAffected()
		return n > 0, nil
	}
	if known, err := touch(); err != nil {
		return true, err
	} else if known {
		return true, nil
	}
	capped := limit <= 0 || limit > MaxUserDevices
	if capped {
		limit = MaxUserDevices
	}
	res, err := DB.Exec(`INSERT INTO user_devices (user_id, hwid, os, os_version, model, first_seen, last_seen)
		SELECT ?, ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM user_devices WHERE user_id = ?) < ?
		ON CONFLICT(user_id, hwid) DO NOTHING`,
		userID, hwid, d.OS, d.OSVersion, d.Model, now, now, userID, limit)
	if err != nil {
		return true, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Либо лимит исчерпан, либо тот же HWID успел записать параллельный запрос.
		if known, _ := touch(); known {
			return true, nil
		}
		if !capped {
			return false, nil
		}
		// Потолок без пользовательского лимита: освобождаем место, вытесняя самое давнее устройство.
		_, _ = DB.Exec(`DELETE FROM user_devices WHERE rowid IN (SELECT rowid FROM user_devices WHERE user_id = ?
			ORDER BY last_seen DESC, rowid DESC LIMIT -1 OFFSET ?)`, userID, MaxUserDevices-1)
		_, err = DB.Exec(`INSERT INTO user_devices (user_id, hwid, os, os_version, model, first_seen, last_seen)
			VALUES (?,?,?,?,?,?,?) ON CONFLICT(user_id, hwid) DO NOTHING`, userID, hwid, d.OS, d.OSVersion, d.Model, now, now)
		return true, err
	}
	return true, nil
}

func ListDevices(userID int) ([]Device, error) {
	rows, err := DB.Query("SELECT rowid, hwid, os, os_version, model, first_seen, last_seen FROM user_devices WHERE user_id = ? ORDER BY first_seen, rowid", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Device{}
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.HWID, &d.OS, &d.OSVersion, &d.Model, &d.FirstSeen, &d.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteDevice удаляет устройство по номеру строки (HWID может содержать любые печатные символы).
func DeleteDevice(userID int, id int64) error {
	_, err := DB.Exec("DELETE FROM user_devices WHERE user_id = ? AND rowid = ?", userID, id)
	return err
}
