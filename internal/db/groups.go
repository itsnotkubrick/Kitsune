package db

import (
	"encoding/json"
	"errors"
	"strings"
)

// Group – группа доступа: пользователи группы видят только перечисленные подключения (как «группы» в Marzban).
// Пользователь без группы (group_id = 0) пользуется всеми подключениями.
type Group struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	InboundIDs []int  `json:"inbound_ids"`
}

// Template – шаблон пользователя: набор лимитов и параметров, из которого создаются новые пользователи.
type Template struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	TrafficLimit int64  `json:"traffic_limit"` // байты, 0 – без лимита
	Days         int    `json:"days"`          // срок в днях, 0 – бессрочно
	IPLimit      int    `json:"ip_limit"`
	Vision       bool   `json:"vision"`
	Note         string `json:"note"`
	GroupID      int    `json:"group_id"`
}

func initGroups() {
	_, _ = DB.Exec(`CREATE TABLE IF NOT EXISTS groups (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		inbound_ids TEXT NOT NULL DEFAULT '[]'
	)`)
	_, _ = DB.Exec(`CREATE TABLE IF NOT EXISTS templates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		traffic_limit BIGINT DEFAULT 0,
		days INTEGER DEFAULT 0,
		ip_limit INTEGER DEFAULT 0,
		vision BOOLEAN DEFAULT 1,
		note TEXT DEFAULT '',
		group_id INTEGER DEFAULT 0
	)`)
	_, _ = DB.Exec("ALTER TABLE users ADD COLUMN group_id INTEGER DEFAULT 0;")
}

func GetGroups() ([]Group, error) {
	if DB == nil {
		return []Group{}, nil
	}
	rows, err := DB.Query("SELECT id, name, inbound_ids FROM groups ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		var g Group
		var raw string
		if err := rows.Scan(&g.ID, &g.Name, &raw); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(raw), &g.InboundIDs)
		if g.InboundIDs == nil {
			g.InboundIDs = []int{}
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func SaveGroup(g Group) (int, error) {
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" {
		return 0, errors.New("укажите название группы")
	}
	raw, _ := json.Marshal(g.InboundIDs)
	if g.ID > 0 {
		_, err := DB.Exec("UPDATE groups SET name = ?, inbound_ids = ? WHERE id = ?", g.Name, string(raw), g.ID)
		return g.ID, err
	}
	res, err := DB.Exec("INSERT INTO groups (name, inbound_ids) VALUES (?, ?)", g.Name, string(raw))
	if err != nil {
		return 0, errors.New("группа с таким названием уже есть")
	}
	id, _ := res.LastInsertId()
	return int(id), nil
}

func DeleteGroup(id int) error {
	_, _ = DB.Exec("UPDATE users SET group_id = 0 WHERE group_id = ?", id)
	_, _ = DB.Exec("UPDATE templates SET group_id = 0 WHERE group_id = ?", id)
	_, err := DB.Exec("DELETE FROM groups WHERE id = ?", id)
	return err
}

// GroupMap – разрешённые подключения по группам: groupID -> набор inboundID. Группы 0 в карте нет (доступно всё).
func GroupMap() map[int]map[int]bool {
	out := map[int]map[int]bool{}
	gs, err := GetGroups()
	if err != nil {
		return out
	}
	for _, g := range gs {
		m := map[int]bool{}
		for _, id := range g.InboundIDs {
			m[id] = true
		}
		out[g.ID] = m
	}
	return out
}

// Allowed: может ли пользователь пользоваться подключением (с учётом группы).
func Allowed(gm map[int]map[int]bool, u User, inboundID int) bool {
	if u.GroupID == 0 {
		return true
	}
	m, ok := gm[u.GroupID]
	if !ok {
		return true // группа удалена – доступ ко всему
	}
	return m[inboundID]
}

func GetTemplates() ([]Template, error) {
	rows, err := DB.Query("SELECT id, name, traffic_limit, days, ip_limit, vision, note, group_id FROM templates ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Template{}
	for rows.Next() {
		var t Template
		var v int
		if err := rows.Scan(&t.ID, &t.Name, &t.TrafficLimit, &t.Days, &t.IPLimit, &v, &t.Note, &t.GroupID); err != nil {
			return nil, err
		}
		t.Vision = v == 1
		out = append(out, t)
	}
	return out, rows.Err()
}

func GetTemplate(id int) (*Template, error) {
	ts, err := GetTemplates()
	if err != nil {
		return nil, err
	}
	for i := range ts {
		if ts[i].ID == id {
			return &ts[i], nil
		}
	}
	return nil, errors.New("шаблон не найден")
}

func SaveTemplate(t Template) (int, error) {
	t.Name = strings.TrimSpace(t.Name)
	if t.Name == "" {
		return 0, errors.New("укажите название шаблона")
	}
	if t.TrafficLimit < 0 || t.Days < 0 || t.IPLimit < 0 {
		return 0, errors.New("значения не могут быть отрицательными")
	}
	if t.ID > 0 {
		_, err := DB.Exec("UPDATE templates SET name=?, traffic_limit=?, days=?, ip_limit=?, vision=?, note=?, group_id=? WHERE id=?",
			t.Name, t.TrafficLimit, t.Days, t.IPLimit, b2i(t.Vision), t.Note, t.GroupID, t.ID)
		return t.ID, err
	}
	res, err := DB.Exec("INSERT INTO templates (name, traffic_limit, days, ip_limit, vision, note, group_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
		t.Name, t.TrafficLimit, t.Days, t.IPLimit, b2i(t.Vision), t.Note, t.GroupID)
	if err != nil {
		return 0, errors.New("шаблон с таким названием уже есть")
	}
	id, _ := res.LastInsertId()
	return int(id), nil
}

func DeleteTemplate(id int) error {
	_, err := DB.Exec("DELETE FROM templates WHERE id = ?", id)
	return err
}
