package importer

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"kitsune/internal/db"
	"kitsune/internal/proto"
)

// Действия в отчёте.
const (
	ActCreate = "create" // будет создано
	ActUpdate = "update" // будет обновлено
	ActExists = "exists" // уже есть, не тронуто
	ActSkip   = "skip"   // пропущено (причина в Reason)
)

// Options – параметры прогона. По умолчанию (Apply=false) в базу ничего не пишется.
type Options struct {
	Apply  bool // false – пробный прогон
	Update bool // обновлять найденных пользователей (иначе пропускать)
	Now    func() time.Time
	// PortReserved – порт занят самой панелью (служебные порты); PortListening – порт сейчас слушает другой процесс.
	PortReserved  func(port int, netw string) bool
	PortListening func(port int) bool
}

// Item – одна строка отчёта. Секретов здесь нет: UUID и subId показываются в маске.
type Item struct {
	Name     string `json:"name"`
	Action   string `json:"action"`
	Reason   string `json:"reason,omitempty"`
	Details  string `json:"details,omitempty"`
	Conflict bool   `json:"conflict,omitempty"`
}

type Counts struct {
	Create    int `json:"create"`
	Update    int `json:"update"`
	Exists    int `json:"exists"`
	Skip      int `json:"skip"`
	Conflicts int `json:"conflicts"`
}

type Report struct {
	Source   string `json:"source"`
	Applied  bool   `json:"applied"`
	Update   bool   `json:"update"`
	Users    []Item `json:"users"`
	Inbounds []Item `json:"inbounds"`
	// Сколько строк не показано (список обрезан Limit); итоги в UserSum и InSum считаются по всем.
	UsersMore    int      `json:"users_more,omitempty"`
	InboundsMore int      `json:"inbounds_more,omitempty"`
	UserSum      Counts   `json:"user_sum"`
	InSum        Counts   `json:"inbound_sum"`
	Notes        []string `json:"notes,omitempty"`
	// Warnings – то, что нужно прочитать до подтверждения.
	Warnings []string `json:"warnings,omitempty"`
}

// AccessWarning – предупреждение о доступе импортированных пользователей.
const AccessWarning = "Импортированные пользователи получат доступ ко всем подключениям Kitsune (в Kitsune доступ задаётся группами)"

// Limit оставляет в списках не больше n строк (сначала конфликты и пропуски, потом остальные), итоги не меняются.
// Нужен, чтобы отчёт на десятки тысяч пользователей не вешал страницу и консоль.
func (r *Report) Limit(n int) {
	var mu, mi int
	r.Users, mu = limitItems(r.Users, n)
	r.Inbounds, mi = limitItems(r.Inbounds, n)
	r.UsersMore += mu
	r.InboundsMore += mi
}

func limitItems(items []Item, n int) ([]Item, int) {
	if len(items) <= n {
		return items, 0
	}
	out := make([]Item, 0, n)
	for _, pass := range []bool{true, false} {
		for _, it := range items {
			if len(out) < n && (it.Conflict || it.Action == ActSkip) == pass {
				out = append(out, it)
			}
		}
	}
	return out, len(items) - len(out)
}

func (c *Counts) add(it Item) {
	switch it.Action {
	case ActCreate:
		c.Create++
	case ActUpdate:
		c.Update++
	case ActExists:
		c.Exists++
	default:
		c.Skip++
	}
	if it.Conflict {
		c.Conflicts++
	}
}

type querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
	Exec(query string, args ...any) (sql.Result, error)
}

// Run строит отчёт; при Apply=true ещё и записывает всё в одной транзакции (ошибка откатывает всё).
// Резервную копию базы Kitsune делает вызывающий код до Run.
func Run(kdb *sql.DB, d *Data, opt Options) (*Report, error) {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if !opt.Apply {
		return execute(kdb, d, opt)
	}
	tx, err := kdb.Begin()
	if err != nil {
		return nil, err
	}
	rep, err := execute(tx, d, opt)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, errors.New("не удалось сохранить изменения")
	}
	return rep, nil
}

type exUser struct {
	id        int
	name, sub string
	uuid      string
	batch     bool
}

type exInbound struct {
	id        int
	tag, kind string
	port      int
}

func netOf(kind string) string {
	if info, ok := proto.Get(proto.Kind(kind)); ok {
		return info.Net
	}
	return "tcp"
}

func sameNet(a, b string) bool { return a == "both" || b == "both" || a == b }

func protocolName(k proto.Kind) string {
	switch k {
	case proto.VlessReality, proto.VlessXHTTP, proto.VlessWS:
		return "vless"
	case proto.TrojanGRPC:
		return "trojan"
	case proto.VmessWS:
		return "vmess"
	case proto.SS2022:
		return "shadowsocks"
	case proto.Hysteria2:
		return "hysteria"
	}
	return string(k)
}

func execute(q querier, d *Data, opt Options) (*Report, error) {
	rep := &Report{Source: d.Source, Applied: opt.Apply, Update: opt.Update, Notes: append([]string(nil), d.Notes...)}
	if len(d.Users) > MaxUsers || len(d.Inbounds) > MaxInbounds {
		return nil, errors.New("слишком много записей")
	}

	// Что уже есть в Kitsune.
	var users []*exUser
	rows, err := q.Query("SELECT id, name, sub_id, uuid FROM users")
	if err != nil {
		return nil, errors.New("не удалось прочитать пользователей Kitsune")
	}
	for rows.Next() {
		u := &exUser{}
		if err := rows.Scan(&u.id, &u.name, &u.sub, &u.uuid); err != nil {
			rows.Close()
			return nil, err
		}
		u.uuid = strings.ToLower(u.uuid)
		users = append(users, u)
	}
	rows.Close()
	byName, bySub, byUUID := map[string]*exUser{}, map[string]*exUser{}, map[string]*exUser{}
	reg := func(u *exUser) { byName[u.name], bySub[u.sub], byUUID[u.uuid] = u, u, u }
	for _, u := range users {
		reg(u)
	}
	var inbs []exInbound
	rows, err = q.Query("SELECT id, tag, COALESCE(kind, ''), port FROM inbounds ORDER BY id")
	if err != nil {
		return nil, errors.New("не удалось прочитать подключения Kitsune")
	}
	for rows.Next() {
		var i exInbound
		if err := rows.Scan(&i.id, &i.tag, &i.kind, &i.port); err != nil {
			rows.Close()
			return nil, err
		}
		inbs = append(inbs, i)
	}
	rows.Close()
	tags := map[string]bool{}
	for _, i := range inbs {
		tags[i.tag] = true
	}

	// Подключения.
	for _, si := range d.Inbounds {
		it := Item{Name: si.Name}
		add := func() { rep.Inbounds = append(rep.Inbounds, it); rep.InSum.add(it) }
		if si.Kind == "" {
			it.Action, it.Reason = ActSkip, si.SkipReason
			add()
			continue
		}
		info, _ := proto.Get(si.Kind)
		it.Details = fmt.Sprintf("%s, порт %d", info.Title, si.Port)
		var clash *exInbound
		for i := range inbs {
			if inbs[i].port == si.Port && sameNet(netOf(inbs[i].kind), info.Net) {
				clash = &inbs[i]
				break
			}
		}
		switch {
		case clash != nil && clash.kind == string(si.Kind):
			it.Action, it.Reason = ActExists, "подключение с этим типом и портом уже есть («"+clash.tag+"»)"
			add()
			continue
		case clash != nil:
			it.Action, it.Reason, it.Conflict = ActSkip, fmt.Sprintf("порт %d уже занят подключением «%s»", si.Port, clash.tag), true
			add()
			continue
		case opt.PortReserved != nil && opt.PortReserved(si.Port, info.Net):
			it.Action, it.Reason, it.Conflict = ActSkip, fmt.Sprintf("порт %d занят самой панелью", si.Port), true
			add()
			continue
		}
		s := si.Settings
		if err := s.Fill(si.Kind); err != nil {
			it.Action, it.Reason = ActSkip, "не удалось подготовить настройки"
			add()
			continue
		}
		tag := db.CleanName(si.Name)
		if tag == "" {
			tag = info.Tag
		}
		base := tag
		for n := 2; tags[tag]; n++ {
			tag = fmt.Sprintf("%s-%d", base, n)
		}
		tags[tag] = true
		it.Name, it.Action = tag, ActCreate
		var rs []string
		if tag != base {
			rs = append(rs, "тег занят, добавлен номер")
		}
		rs = append(rs, si.Warnings...)
		if opt.PortListening != nil && opt.PortListening(si.Port) {
			rs = append(rs, fmt.Sprintf("порт %d сейчас слушает другая программа: остановите прежнюю панель", si.Port))
		}
		it.Reason = strings.Join(rs, "; ")
		id := 0
		if opt.Apply {
			en := 0
			if si.Enable {
				en = 1
			}
			res, err := q.Exec(`INSERT INTO inbounds (tag, protocol, port, enable, sni, private_key, public_key, short_id, kind, settings)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				tag, protocolName(si.Kind), si.Port, en, s.SNI, s.PrivateKey, s.PublicKey, s.ShortIDs, string(si.Kind), s.JSON())
			if err != nil {
				return nil, errors.New("не удалось создать подключение «" + tag + "»")
			}
			n, _ := res.LastInsertId()
			id = int(n)
		}
		inbs = append(inbs, exInbound{id: id, tag: tag, kind: string(si.Kind), port: si.Port})
		add()
	}

	// Пользователи.
	noInbounds := 0
	for _, su := range d.Users {
		name, orig := userName(su.Name)
		it := Item{Name: name}
		add := func() { rep.Users = append(rep.Users, it); rep.UserSum.add(it) }
		if su.TrafficLimit < 0 || su.ExpiryMs < 0 {
			it.Action, it.Reason = ActSkip, "некорректные лимит или срок в источнике: "+strings.Join(su.Warnings, ", ")
			add()
			continue
		}
		uid := strings.ToLower(su.UUID)
		expiry := su.ExpiryMs
		if expiry == 0 && su.DelayedMs > 0 {
			expiry = opt.Now().UnixMilli() + su.DelayedMs
		}
		it.Details = describeUser(su, expiry, uid)

		var ex *exUser
		switch {
		case su.SubID != "" && bySub[su.SubID] != nil:
			ex = bySub[su.SubID]
		case uid != "" && byUUID[uid] != nil:
			ex = byUUID[uid]
		case su.SubID == "" && uid == "" && byName[name] != nil && !byName[name].batch:
			ex = byName[name]
			// Если имя занято пользователем этого же прогона, это другой человек с похожим именем: он получит name_2.
		}
		if ex != nil {
			it.Name = ex.name
			switch {
			case ex.batch:
				it.Action, it.Reason = ActExists, "дубль в источнике: уже учтён выше"
			case !opt.Update:
				it.Action, it.Reason = ActExists, "уже есть в Kitsune, пропущено (режим «пропускать»)"
			default:
				// Отложенный старт отсчитывается один раз, при первом импорте: повторное обновление срок не двигает.
				keepExpiry := su.ExpiryMs == 0 && su.DelayedMs > 0
				it.Action, it.Reason = ActUpdate, "обновятся лимит, статус, число устройств и заметка; трафик и ключи не трогаются"
				if keepExpiry {
					it.Reason += "; срок отложенного старта не пересчитывается"
				} else {
					it.Reason = strings.Replace(it.Reason, "лимит, статус", "лимит, срок, статус", 1)
				}
				if opt.Apply {
					if err := updateUser(q, ex.id, su, expiry, keepExpiry); err != nil {
						return nil, errors.New("не удалось обновить пользователя «" + ex.name + "»")
					}
				}
			}
			add()
			continue
		}

		final := name
		var rs []string
		if byName[final] != nil {
			it.Conflict = true
			for n := 2; byName[final] != nil; n++ {
				final = fmt.Sprintf("%s_%d", name, n)
			}
			if byName[name].batch {
				rs = append(rs, fmt.Sprintf("имя «%s» после очистки совпало с другим пользователем источника, создаётся «%s»", name, final))
			} else {
				rs = append(rs, fmt.Sprintf("имя «%s» занято другим пользователем, создаётся «%s»", name, final))
			}
		}
		it.Name, it.Action = final, ActCreate
		rs = append(rs, su.Warnings...)
		sub := su.SubID
		if sub == "" || bySub[sub] != nil {
			sub = randHex(16)
		}
		if uid == "" {
			uid = uuid.New().String()
		}
		pass := su.Password
		if pass == "" {
			pass = randHex(12)
		}
		note := su.Note
		if orig != "" {
			note = strings.TrimSpace("Имя в источнике: " + orig + ". " + note)
			if r := []rune(note); len(r) > maxNoteRunes {
				note = string(r[:maxNoteRunes])
			}
		}
		if su.Used > 0 && len(inbs) == 0 {
			noInbounds++
		}
		it.Reason = strings.Join(rs, "; ")
		id := 0
		if opt.Apply {
			var err error
			if id, err = insertUser(q, final, sub, uid, pass, note, su, expiry, opt.Now()); err != nil {
				return nil, errors.New("не удалось создать пользователя «" + final + "»")
			}
			if su.Used > 0 {
				for i, ib := range inbs {
					u := int64(0)
					if i == 0 {
						u = su.Used
					}
					if _, err := q.Exec(`INSERT INTO clients (inbound_id, user_id, uuid, email, traffic_limit, used_traffic, expiry_time, enable)
						VALUES (?, ?, ?, ?, 0, ?, 0, 1)`, ib.id, id, uid, db.ClientEmail(final, ib.tag), u); err != nil {
						return nil, errors.New("не удалось записать трафик пользователя «" + final + "»")
					}
				}
			}
		}
		reg(&exUser{id: id, name: final, sub: sub, uuid: uid, batch: true})
		add()
	}
	if rep.UserSum.Create > 0 {
		rep.Warnings = append(rep.Warnings, AccessWarning)
	}
	if noInbounds > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("Использованный трафик %d пользователей не перенесён: в Kitsune нет подключений. Сначала создайте подключения, потом запустите импорт (трафик переносится только при создании пользователя).", noInbounds))
	}
	return rep, nil
}

func insertUser(q querier, name, sub, uid, pass, note string, su SrcUser, expiry int64, now time.Time) (int, error) {
	ss := make([]byte, 32)
	_, _ = rand.Read(ss)
	res, err := q.Exec(`INSERT INTO users (name, sub_id, uuid, password, ss_key, traffic_limit, expiry_time, enable, ip_limit, vision, note, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		name, sub, uid, pass, base64.StdEncoding.EncodeToString(ss), su.TrafficLimit, expiry, b2i(su.Enable), su.IPLimit, b2i(su.Vision), note, now.Unix())
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	return int(id), nil
}

func updateUser(q querier, id int, su SrcUser, expiry int64, keepExpiry bool) error {
	// keepExpiry: срок уже посчитан при первом импорте (отложенный старт) и остаётся как есть.
	_, err := q.Exec(`UPDATE users SET traffic_limit = ?, expiry_time = CASE WHEN ? THEN expiry_time ELSE ? END, enable = ?, ip_limit = ?,
		note = CASE WHEN ? <> '' THEN ? ELSE note END WHERE id = ?`,
		su.TrafficLimit, keepExpiry, expiry, b2i(su.Enable), su.IPLimit, su.Note, su.Note, id)
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// userName делает из имени источника безопасное имя Kitsune. Второе значение – исходное имя, если оно изменилось.
func userName(raw string) (name, orig string) {
	s := cleanText(raw, 120)
	base := s
	if i := strings.Index(s, "@"); i > 0 {
		base = s[:i]
	}
	name = db.CleanName(base)
	if name == "" {
		h := sha256.Sum256([]byte(s))
		name = "user_" + hex.EncodeToString(h[:3])
	}
	if name != s {
		orig = s
	}
	return
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func describeUser(su SrcUser, expiry int64, uid string) string {
	var p []string
	if su.TrafficLimit > 0 {
		p = append(p, "лимит "+humanBytes(su.TrafficLimit))
	} else {
		p = append(p, "без лимита")
	}
	p = append(p, "использовано "+humanBytes(su.Used))
	if expiry > 0 {
		p = append(p, "до "+time.UnixMilli(expiry).UTC().Format("2006-01-02"))
	} else {
		p = append(p, "бессрочно")
	}
	if su.IPLimit > 0 {
		p = append(p, fmt.Sprintf("устройств %d", su.IPLimit))
	}
	if !su.Enable {
		p = append(p, "отключён")
	}
	if uid != "" {
		p = append(p, "uuid "+mask(uid))
	}
	if su.SubID != "" {
		p = append(p, "подписка "+mask(su.SubID))
	}
	return strings.Join(p, ", ")
}

func humanBytes(n int64) string {
	const k = 1024.0
	f := float64(n)
	for _, u := range []string{"Б", "КБ", "МБ", "ГБ", "ТБ"} {
		if f < k || u == "ТБ" {
			if u == "Б" {
				return fmt.Sprintf("%d Б", n)
			}
			return fmt.Sprintf("%.1f %s", f, u)
		}
		f /= k
	}
	return ""
}
