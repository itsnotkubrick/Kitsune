package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type Inbound struct {
	ID         int    `json:"id"`
	Tag        string `json:"tag"`
	Protocol   string `json:"protocol"`
	Port       int    `json:"port"`
	Enable     bool   `json:"enable"`
	SNI        string `json:"sni"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ShortID    string `json:"short_id"`
	// Kind – тип подключения из каталога протоколов (vless-reality, hysteria2, tuic…).
	Kind string `json:"kind"`
	// Settings – параметры подключения в JSON (см. internal/proto.Settings).
	Settings string `json:"settings"`
}

type Client struct {
	ID           int    `json:"id"`
	InboundID    int    `json:"inbound_id"`
	UUID         string `json:"uuid"`
	Email        string `json:"email"`
	TrafficLimit int64  `json:"traffic_limit"`
	UsedTraffic  int64  `json:"used_traffic"`
	ExpiryTime   int64  `json:"expiry_time"`
	Enable       bool   `json:"enable"`
	UserID       int    `json:"user_id"`
}

var DB *sql.DB

func InitDB() {
	dbPath := "kitsune.db"
	// SQLite uses the main file's permissions when creating WAL and SHM.
	// Secure it before opening SQLite and tighten files from older installs.
	f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		log.Fatalf("Ошибка подготовки базы данных: %v", err)
	}
	if err := f.Close(); err != nil {
		log.Fatalf("Ошибка подготовки базы данных: %v", err)
	}
	for _, path := range []string{dbPath, dbPath + "-wal", dbPath + "-shm", dbPath + "-journal"} {
		if err := os.Chmod(path, 0o600); err != nil && (path == dbPath || !errors.Is(err, os.ErrNotExist)) {
			log.Fatalf("Не удалось ограничить права %s: %v", path, err)
		}
	}
	DB, err = sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(0)")
	if err != nil {
		log.Fatalf("Ошибка открытия базы данных: %v", err)
	}

	createInboundsTable := `
	CREATE TABLE IF NOT EXISTS inbounds (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		tag TEXT NOT NULL UNIQUE,
		protocol TEXT NOT NULL,
		port INTEGER NOT NULL,
		enable BOOLEAN DEFAULT 1,
		sni TEXT DEFAULT '',
		private_key TEXT DEFAULT '',
		public_key TEXT DEFAULT '',
		short_id TEXT DEFAULT ''
	);
	`
	if _, err = DB.Exec(createInboundsTable); err != nil {
		log.Fatalf("Ошибка создания таблицы inbounds: %v", err)
	}

	// Миграции для Reality
	_, _ = DB.Exec("ALTER TABLE inbounds ADD COLUMN sni TEXT DEFAULT '';")
	_, _ = DB.Exec("ALTER TABLE inbounds ADD COLUMN private_key TEXT DEFAULT '';")
	_, _ = DB.Exec("ALTER TABLE inbounds ADD COLUMN public_key TEXT DEFAULT '';")
	_, _ = DB.Exec("ALTER TABLE inbounds ADD COLUMN short_id TEXT DEFAULT '';")

	_, _ = DB.Exec("ALTER TABLE inbounds ADD COLUMN kind TEXT DEFAULT '';")
	_, _ = DB.Exec("ALTER TABLE inbounds ADD COLUMN settings TEXT DEFAULT '';")

	createClientsTable := `
	CREATE TABLE IF NOT EXISTS clients (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		inbound_id INTEGER,
		uuid TEXT NOT NULL,
		email TEXT NOT NULL,
		traffic_limit BIGINT DEFAULT 0,
		used_traffic BIGINT DEFAULT 0,
		expiry_time BIGINT DEFAULT 0,
		enable BOOLEAN DEFAULT 1,
		FOREIGN KEY (inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE
	);
	`
	if _, err = DB.Exec(createClientsTable); err != nil {
		log.Fatalf("Ошибка создания таблицы clients: %v", err)
	}

	_, _ = DB.Exec("ALTER TABLE clients ADD COLUMN traffic_limit BIGINT DEFAULT 0;")
	_, _ = DB.Exec("ALTER TABLE clients ADD COLUMN used_traffic BIGINT DEFAULT 0;")
	_, _ = DB.Exec("ALTER TABLE clients ADD COLUMN expiry_time BIGINT DEFAULT 0;")
	_, _ = DB.Exec("ALTER TABLE clients ADD COLUMN user_id INTEGER DEFAULT 0;")
	_, _ = DB.Exec("ALTER TABLE clients ADD COLUMN data TEXT DEFAULT '';")

	initUsers()
	initDevices()
	initConnect()
	initPassport()
	initStability()

	createSettingsTable := `
	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);
	`
	if _, err = DB.Exec(createSettingsTable); err != nil {
		log.Fatalf("Ошибка создания таблицы settings: %v", err)
	}

	initAdminCredentials()
	initMTProtoSalt()

	log.Println("База данных Kitsune успешно инициализирована")
}

func hashPassword(p string) string {
	h, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Не удалось захешировать пароль: %v", err)
	}
	return string(h)
}

func isHash(v string) bool {
	return strings.HasPrefix(v, "$2a$") || strings.HasPrefix(v, "$2b$") || strings.HasPrefix(v, "$2y$")
}

func initAdminCredentials() {
	var user, pass string
	errU := DB.QueryRow("SELECT value FROM settings WHERE key = 'admin_username'").Scan(&user)
	errP := DB.QueryRow("SELECT value FROM settings WHERE key = 'admin_password'").Scan(&pass)

	if errU != nil || errP != nil {
		adminUser := RandomAlnum(10) // случайный логин: «admin» первым делом перебирают
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		adminPass := hex.EncodeToString(b)

		_, _ = DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_username', ?)", adminUser)
		_, _ = DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password', ?)", hashPassword(adminPass))

		_, _ = DB.Exec("INSERT OR IGNORE INTO settings (key, value) VALUES ('panel_path', ?)", RandomSlug(10))

		log.Println("==================================================")
		log.Printf("🔐 ADMIN CREDENTIALS CREATED:")
		log.Printf("   Login   : %s", adminUser)
		log.Printf("   Password: %s", adminPass)
		log.Println("==================================================")
		return
	}
	// Базы прежних версий хранили пароль открытым текстом – переводим на bcrypt.
	if !isHash(pass) {
		_, _ = DB.Exec("UPDATE settings SET value = ? WHERE key = 'admin_password'", hashPassword(pass))
	}
}

func CheckAdminAuth(username, password string) bool {
	var storedUser, storedPass string
	if DB.QueryRow("SELECT value FROM settings WHERE key = 'admin_username'").Scan(&storedUser) != nil ||
		DB.QueryRow("SELECT value FROM settings WHERE key = 'admin_password'").Scan(&storedPass) != nil {
		return false
	}
	if username != storedUser {
		_ = bcrypt.CompareHashAndPassword([]byte(storedPass), []byte(password)) // выравниваем время ответа
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(storedPass), []byte(password)) == nil
}

func UpdateAdminCredentials(username, newPassword string) error {
	_, err := DB.Exec("UPDATE settings SET value = ? WHERE key = 'admin_password'", hashPassword(newPassword))
	if err != nil {
		return err
	}
	// Новая «эпоха» делает недействительными все выданные раньше куки входа: сменили пароль, значит старые сессии не нужны.
	return SetSetting("session_epoch", RandomAlnum(16))
}

// AdminPasswordIs проверяет пароль администратора по хешу (для проверки на слабые пароли).
func AdminPasswordIs(candidate string) bool {
	var stored string
	if DB.QueryRow("SELECT value FROM settings WHERE key = 'admin_password'").Scan(&stored) != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(stored), []byte(candidate)) == nil
}

func GetInbounds() ([]Inbound, error) {
	rows, err := DB.Query("SELECT id, tag, protocol, port, enable, sni, private_key, public_key, short_id, COALESCE(kind, ''), COALESCE(settings, '') FROM inbounds")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var inbounds []Inbound
	for rows.Next() {
		var i Inbound
		var enableInt int
		if err := rows.Scan(&i.ID, &i.Tag, &i.Protocol, &i.Port, &enableInt, &i.SNI, &i.PrivateKey, &i.PublicKey, &i.ShortID, &i.Kind, &i.Settings); err != nil {
			return nil, err
		}
		i.Enable = enableInt == 1
		inbounds = append(inbounds, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return inbounds, nil
}

func GetInboundByID(id int) (*Inbound, error) {
	var i Inbound
	var enableInt int
	err := DB.QueryRow("SELECT id, tag, protocol, port, enable, sni, private_key, public_key, short_id, COALESCE(kind, ''), COALESCE(settings, '') FROM inbounds WHERE id = ?", id).
		Scan(&i.ID, &i.Tag, &i.Protocol, &i.Port, &enableInt, &i.SNI, &i.PrivateKey, &i.PublicKey, &i.ShortID, &i.Kind, &i.Settings)
	if err != nil {
		return nil, err
	}
	i.Enable = enableInt == 1
	return &i, nil
}

func GetClientsByInbound(inboundID int) ([]Client, error) {
	rows, err := DB.Query("SELECT id, inbound_id, uuid, email, traffic_limit, used_traffic, expiry_time, enable, COALESCE(user_id, 0) FROM clients WHERE inbound_id = ?", inboundID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []Client
	for rows.Next() {
		var c Client
		var enableInt int
		if err := rows.Scan(&c.ID, &c.InboundID, &c.UUID, &c.Email, &c.TrafficLimit, &c.UsedTraffic, &c.ExpiryTime, &enableInt, &c.UserID); err != nil {
			return nil, err
		}
		c.Enable = enableInt == 1
		clients = append(clients, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return clients, nil
}

func GetAllActiveClients() ([]Client, error) {
	rows, err := DB.Query("SELECT id, inbound_id, uuid, email, traffic_limit, used_traffic, expiry_time, enable, COALESCE(user_id, 0) FROM clients WHERE enable = 1")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []Client
	for rows.Next() {
		var c Client
		var enableInt int
		if err := rows.Scan(&c.ID, &c.InboundID, &c.UUID, &c.Email, &c.TrafficLimit, &c.UsedTraffic, &c.ExpiryTime, &enableInt, &c.UserID); err != nil {
			return nil, err
		}
		c.Enable = enableInt == 1
		clients = append(clients, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return clients, nil
}

func AddClient(inboundID int, uuid, email string, trafficLimit, expiryMs int64) error {
	_, err := DB.Exec("INSERT INTO clients (inbound_id, uuid, email, traffic_limit, used_traffic, expiry_time, enable) VALUES (?, ?, ?, ?, 0, ?, 1)",
		inboundID, uuid, email, trafficLimit, expiryMs)
	return err
}

func DeleteClient(clientID int) error {
	_, err := DB.Exec("DELETE FROM clients WHERE id = ?", clientID)
	return err
}

func ToggleClientStatus(clientID int) error {
	_, err := DB.Exec("UPDATE clients SET enable = CASE WHEN enable = 1 THEN 0 ELSE 1 END WHERE id = ?", clientID)
	return err
}

func DisableClient(clientID int) error {
	_, err := DB.Exec("UPDATE clients SET enable = 0 WHERE id = ?", clientID)
	return err
}

func ResetClientTraffic(clientID int) error {
	_, err := DB.Exec("UPDATE clients SET used_traffic = 0 WHERE id = ?", clientID)
	return err
}

func IncrementClientTraffic(email string, bytes int64) error {
	_, err := DB.Exec("UPDATE clients SET used_traffic = used_traffic + ? WHERE email = ?", bytes, email)
	return err
}

func NowPlusDays(days int) int64 {
	return time.Now().AddDate(0, 0, days).UnixNano() / int64(time.Millisecond)
}

// GetSetting читает значение из таблицы settings; def возвращается, если ключа нет.
func GetSetting(key, def string) string {
	if DB == nil {
		return def
	}
	var v string
	if err := DB.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&v); err != nil {
		return def
	}
	return v
}

// LookupSetting отличает «настройки нет» (found=false, err=nil) от ошибки чтения базы.
func LookupSetting(key string) (value string, found bool, err error) {
	if DB == nil {
		return "", false, errors.New("база не открыта")
	}
	err = DB.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

func SetSetting(key, value string) error {
	_, err := DB.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", key, value)
	return err
}

// Snapshot сохраняет согласованную копию базы в файл (без остановки панели).
func Snapshot(path string) error {
	_ = os.Remove(path)
	if _, err := DB.Exec("VACUUM INTO ?", path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// Replace подменяет рабочую базу файлом newFile и открывает её заново (восстановление из копии).
func Replace(newFile string) error {
	if DB != nil {
		_ = DB.Close()
	}
	for _, ext := range []string{"-wal", "-shm"} {
		_ = os.Remove("kitsune.db" + ext)
	}
	if err := os.Rename(newFile, "kitsune.db"); err != nil {
		InitDB()
		return err
	}
	InitDB()
	return nil
}

// RandomSlug – случайная строка из строчных латинских букв и цифр (для секретного пути панели).
func RandomSlug(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// RandomAlnum – случайная строка из букв обоих регистров и цифр (логин администратора).
func RandomAlnum(n int) string {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}
