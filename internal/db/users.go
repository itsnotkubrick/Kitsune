package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// User – пользователь панели: один человек, одна подписка, доступ сразу во все включённые подключения.
// Лимиты (трафик, срок, число устройств) общие на всех протоколах. Строки таблицы clients – это
// «членство» пользователя в конкретном подключении (по ним Xray считает трафик).
type User struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	SubID        string `json:"sub_id"`
	UUID         string `json:"uuid"`
	Password     string `json:"password"`
	SSKey        string `json:"-"`
	TrafficLimit int64  `json:"traffic_limit"`
	UsedTraffic  int64  `json:"used_traffic"`
	ExpiryTime   int64  `json:"expiry_time"`
	Enable       bool   `json:"enable"`
	IPLimit      int    `json:"ip_limit"`
	Vision       bool   `json:"vision"`
	Note         string `json:"note"`
	CreatedAt    int64  `json:"created_at"`
	GroupID      int    `json:"group_id"`
}

// Active – может ли пользователь сейчас пользоваться сервером.
func (u User) Active() bool {
	if !u.Enable {
		return false
	}
	if u.TrafficLimit > 0 && u.UsedTraffic >= u.TrafficLimit {
		return false
	}
	if u.ExpiryTime > 0 && u.ExpiryTime < time.Now().UnixMilli() {
		return false
	}
	return true
}

// SSKey16 – ключ пользователя для методов Shadowsocks 2022 с 16-байтным ключом (aes-128-gcm).
func (u User) SSKey16() string {
	raw, err := base64.StdEncoding.DecodeString(u.SSKey)
	if err != nil || len(raw) < 16 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(raw[:16])
}

// SSKey32 – ключ для методов с 32-байтным ключом (aes-256-gcm, chacha20-poly1305).
func (u User) SSKey32() string { return u.SSKey }

const userCols = `id, name, sub_id, uuid, password, ss_key, traffic_limit, expiry_time, enable, ip_limit, vision, note, created_at,
	COALESCE((SELECT SUM(used_traffic) FROM clients WHERE clients.user_id = users.id), 0), COALESCE(group_id, 0)`

func scanUser(sc interface{ Scan(...any) error }) (User, error) {
	var u User
	var en, vis int
	err := sc.Scan(&u.ID, &u.Name, &u.SubID, &u.UUID, &u.Password, &u.SSKey, &u.TrafficLimit, &u.ExpiryTime, &en, &u.IPLimit, &vis, &u.Note, &u.CreatedAt, &u.UsedTraffic, &u.GroupID)
	u.Enable, u.Vision = en == 1, vis == 1
	return u, err
}

func initUsers() {
	_, err := DB.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		sub_id TEXT NOT NULL UNIQUE,
		uuid TEXT NOT NULL,
		password TEXT NOT NULL,
		ss_key TEXT NOT NULL,
		traffic_limit BIGINT DEFAULT 0,
		expiry_time BIGINT DEFAULT 0,
		enable BOOLEAN DEFAULT 1,
		ip_limit INTEGER DEFAULT 0,
		vision BOOLEAN DEFAULT 1,
		note TEXT DEFAULT '',
		created_at BIGINT DEFAULT 0
	)`)
	if err != nil {
		return
	}
	initGroups()
	migrateLegacyClients()
}

// migrateLegacyClients превращает клиентов старого формата (по одному на подключение) в пользователей.
func migrateLegacyClients() {
	rows, err := DB.Query("SELECT id, uuid, email, traffic_limit, expiry_time, enable FROM clients WHERE COALESCE(user_id, 0) = 0")
	if err != nil {
		return
	}
	type old struct {
		id, en        int
		uuid, email   string
		limit, expiry int64
	}
	var olds []old
	for rows.Next() {
		var o old
		if rows.Scan(&o.id, &o.uuid, &o.email, &o.limit, &o.expiry, &o.en) == nil {
			olds = append(olds, o)
		}
	}
	rows.Close()
	for _, o := range olds {
		name := strings.SplitN(o.email, "@", 2)[0]
		u, err := CreateUser(name, o.limit, o.expiry, 0)
		if err != nil {
			continue
		}
		_, _ = DB.Exec("UPDATE users SET uuid = ?, enable = ? WHERE id = ?", o.uuid, o.en, u.ID)
		_, _ = DB.Exec("UPDATE clients SET user_id = ? WHERE id = ?", u.ID, o.id)
	}
}

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var nameRe = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

// CleanName приводит имя к безопасному виду для логов Xray и ссылок.
func CleanName(s string) string {
	s = nameRe.ReplaceAllString(strings.TrimSpace(s), "_")
	s = strings.Trim(s, "_.-")
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

// CreateUser создаёт пользователя (идентификатор подписки – 128 бит, 32 символа; старые, более короткие, остаются рабочими); имя делается уникальным, если уже занято.
func CreateUser(name string, trafficLimit, expiryMs int64, ipLimit int) (*User, error) {
	name = CleanName(name)
	if name == "" {
		name = "user_" + randHex(3)
	}
	base := name
	for i := 2; ; i++ {
		var n int
		_ = DB.QueryRow("SELECT COUNT(*) FROM users WHERE name = ?", name).Scan(&n)
		if n == 0 {
			break
		}
		name = fmt.Sprintf("%s_%d", base, i)
	}
	res, err := DB.Exec(`INSERT INTO users (name, sub_id, uuid, password, ss_key, traffic_limit, expiry_time, enable, ip_limit, vision, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 1, ?)`,
		name, randHex(16), uuid.New().String(), randHex(12), randB64(32), trafficLimit, expiryMs, ipLimit, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return GetUser(int(id))
}

func GetUser(id int) (*User, error) {
	u, err := scanUser(DB.QueryRow("SELECT "+userCols+" FROM users WHERE id = ?", id))
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func GetUserBySubID(subID string) (*User, error) {
	u, err := scanUser(DB.QueryRow("SELECT "+userCols+" FROM users WHERE sub_id = ?", subID))
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func GetUsers() ([]User, error) {
	rows, err := DB.Query("SELECT " + userCols + " FROM users ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

type UserPatch struct {
	Name         *string `json:"name"`
	TrafficLimit *int64  `json:"traffic_limit"`
	ExpiryTime   *int64  `json:"expiry_time"`
	Enable       *bool   `json:"enable"`
	IPLimit      *int    `json:"ip_limit"`
	Vision       *bool   `json:"vision"`
	Note         *string `json:"note"`
	GroupID      *int    `json:"group_id"`
}

func UpdateUser(id int, p UserPatch) error {
	set := func(col string, v any) error {
		_, err := DB.Exec("UPDATE users SET "+col+" = ? WHERE id = ?", v, id)
		return err
	}
	if p.Name != nil {
		n := CleanName(*p.Name)
		if n == "" {
			return errors.New("пустое имя")
		}
		if err := set("name", n); err != nil {
			return err
		}
	}
	if p.TrafficLimit != nil {
		if err := set("traffic_limit", *p.TrafficLimit); err != nil {
			return err
		}
	}
	if p.ExpiryTime != nil {
		if err := set("expiry_time", *p.ExpiryTime); err != nil {
			return err
		}
	}
	if p.Enable != nil {
		if err := set("enable", b2i(*p.Enable)); err != nil {
			return err
		}
	}
	if p.IPLimit != nil {
		if err := set("ip_limit", *p.IPLimit); err != nil {
			return err
		}
	}
	if p.Vision != nil {
		if err := set("vision", b2i(*p.Vision)); err != nil {
			return err
		}
	}
	if p.Note != nil {
		if err := set("note", *p.Note); err != nil {
			return err
		}
	}
	if p.GroupID != nil {
		if err := set("group_id", *p.GroupID); err != nil {
			return err
		}
	}
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func DeleteUser(id int) error {
	_, _ = DB.Exec("DELETE FROM user_devices WHERE user_id = ?", id)
	_, _ = DB.Exec("DELETE FROM connect_events WHERE user_id = ?", id)
	if _, err := DB.Exec("DELETE FROM clients WHERE user_id = ?", id); err != nil {
		return err
	}
	_, err := DB.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}

func ResetUserTraffic(id int) error {
	_, err := DB.Exec("UPDATE clients SET used_traffic = 0 WHERE user_id = ?", id)
	return err
}

// ClientEmail – имя пользователя в статистике Xray: уникально в пределах подключения.
func ClientEmail(userName, inboundTag string) string {
	return CleanName(userName) + "@" + CleanName(inboundTag)
}

// SyncMembership приводит таблицу clients в соответствие: каждый пользователь есть в каждом подключении.
// Строки удалённых подключений и пользователей убираются, имена обновляются при переименовании.
func SyncMembership() error {
	_, _ = DB.Exec("DELETE FROM clients WHERE COALESCE(user_id, 0) > 0 AND (user_id NOT IN (SELECT id FROM users) OR inbound_id NOT IN (SELECT id FROM inbounds))")
	users, err := GetUsers()
	if err != nil {
		return err
	}
	inbounds, err := GetInbounds()
	if err != nil {
		return err
	}
	gm := GroupMap()
	for _, u := range users {
		for _, ib := range inbounds {
			if !Allowed(gm, u, ib.ID) {
				continue // доступа нет; прежние строки (с историей трафика) не трогаем
			}
			email := ClientEmail(u.Name, ib.Tag)
			var id int
			err := DB.QueryRow("SELECT id FROM clients WHERE user_id = ? AND inbound_id = ?", u.ID, ib.ID).Scan(&id)
			switch {
			case errors.Is(err, sql.ErrNoRows):
				if _, err := DB.Exec(`INSERT INTO clients (inbound_id, user_id, uuid, email, traffic_limit, used_traffic, expiry_time, enable)
					VALUES (?, ?, ?, ?, 0, 0, 0, 1)`, ib.ID, u.ID, u.UUID, email); err != nil {
					return err
				}
			case err == nil:
				_, _ = DB.Exec("UPDATE clients SET email = ?, uuid = ? WHERE id = ?", email, u.UUID, id)
			default:
				return err
			}
		}
	}
	return nil
}

// UserByEmail находит пользователя по имени в статистике Xray (user>>>email>>>traffic).
func UserByEmail(email string) (*User, error) {
	var uid int
	if err := DB.QueryRow("SELECT user_id FROM clients WHERE email = ? LIMIT 1", email).Scan(&uid); err != nil {
		return nil, err
	}
	return GetUser(uid)
}

// ClientData – данные пользователя в подключении (например, ключи и адрес пира AmneziaWG), JSON или пусто.
func ClientData(userID, inboundID int) string {
	var d string
	_ = DB.QueryRow("SELECT COALESCE(data, '') FROM clients WHERE user_id = ? AND inbound_id = ?", userID, inboundID).Scan(&d)
	return d
}

func SetClientData(userID, inboundID int, data string) error {
	_, err := DB.Exec("UPDATE clients SET data = ? WHERE user_id = ? AND inbound_id = ?", data, userID, inboundID)
	return err
}

// ClientDataByInbound – все данные пользователей подключения: user_id -> JSON.
func ClientDataByInbound(inboundID int) map[int]string {
	out := map[int]string{}
	rows, err := DB.Query("SELECT user_id, COALESCE(data, '') FROM clients WHERE inbound_id = ? AND COALESCE(user_id, 0) > 0", inboundID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var uid int
		var d string
		if rows.Scan(&uid, &d) == nil {
			out[uid] = d
		}
	}
	return out
}

// RegenSubID выдаёт пользователю новый идентификатор подписки: старая ссылка и QR перестают работать,
// ключи подключений (uuid, пароли) остаются прежними. Нужен, если ссылка попала не в те руки.
func RegenSubID(id int) (string, error) {
	nsub := randHex(16)
	res, err := DB.Exec("UPDATE users SET sub_id = ? WHERE id = ?", nsub, id)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", sql.ErrNoRows
	}
	return nsub, nil
}
