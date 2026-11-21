package db

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"sync"
)

// Соль установки для личных секретов MTProto (telemt): 32 случайных байта в hex, создаётся при первом запуске
// и больше не меняется. Лежит только в таблице settings; наружу (API, логи, подписка) не выводится.
const mtprotoSaltKey = "mtproto_salt"

var (
	saltMu    sync.Mutex
	saltValue string
)

// initMTProtoSalt читает соль из базы или создаёт её, если её ещё нет (новая установка и обновление старой).
// Если соль получить не удалось, она остаётся пустой: личные секреты MTProto при этом не выдаются.
func initMTProtoSalt() {
	saltMu.Lock()
	defer saltMu.Unlock()
	saltValue = ""
	v, created, err := ensureMTProtoSalt()
	if err != nil {
		log.Printf("Соль MTProto недоступна, личные секреты MTProto (telemt) не выдаются: %v", err)
		return
	}
	if created {
		var users int
		if DB.QueryRow("SELECT COUNT(*) FROM clients").Scan(&users) == nil && users > 0 {
			log.Printf("Соль MTProto создана заново: личные ссылки MTProto (telemt) у пользователей изменились, раздайте их снова")
		}
	}
	saltValue = v
}

func validSalt(v string) bool {
	if len(v) != 64 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}

// ensureMTProtoSalt возвращает соль из базы; created=true, если пришлось создать новую (или заменить повреждённую).
// Запись идёт через INSERT OR IGNORE / условный UPDATE и повторное чтение: если соль одновременно создаёт
// другой процесс (панель, cli, второй запуск), побеждает один вариант, и все читают именно его.
func ensureMTProtoSalt() (salt string, created bool, err error) {
	if DB == nil {
		return "", false, errors.New("база не открыта")
	}
	v, found, err := LookupSetting(mtprotoSaltKey)
	if err != nil {
		return "", false, err
	}
	if found && validSalt(v) {
		return v, false, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("Не удалось создать соль MTProto: %v", err)
	}
	fresh := hex.EncodeToString(b)
	if _, err := DB.Exec("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", mtprotoSaltKey, fresh); err != nil {
		return "", false, err
	}
	// строка могла уже быть, но с повреждённым значением: заменяем только его
	if _, err := DB.Exec("UPDATE settings SET value = ? WHERE key = ? AND length(value) <> 64", fresh, mtprotoSaltKey); err != nil {
		return "", false, err
	}
	v, found, err = LookupSetting(mtprotoSaltKey)
	if err != nil {
		return "", false, err
	}
	if !found || !validSalt(v) {
		return "", false, errors.New("соль не сохранилась")
	}
	return v, true, nil
}

// MTProtoSalt – соль установки для секретов MTProto. Пустая строка, если соль недоступна (база не открыта, не удалось сохранить).
func MTProtoSalt() string {
	saltMu.Lock()
	defer saltMu.Unlock()
	return saltValue
}
