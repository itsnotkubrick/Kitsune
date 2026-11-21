package importer

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
)

// ReadMarzban читает базу Marzban (SQLite): пользователи и их прокси. Подключения Marzban живут в config.json
// Xray, а не в базе, поэтому здесь переносятся только пользователи; теги подключений идут в отчёт как справка.
func ReadMarzban(path string, opts ...ReadOpt) (*Data, error) {
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()
	d, closeDB, err := openCopy(ctx, path, newReadCfg(opts))
	if err != nil {
		return nil, err
	}
	defer closeDB()
	return readMarzban(ctx, d)
}

func readMarzban(ctx context.Context, d *sql.DB) (*Data, error) {
	uc := tableCols(ctx, d, "users")
	for _, c := range []string{"username", "used_traffic", "data_limit", "expire"} {
		if !uc[c] {
			return nil, errors.New("это не база Marzban: нет таблицы users нужной схемы")
		}
	}
	urows, err := selectRows(ctx, d, "users", uc, []string{"id", "username", "status", "used_traffic", "data_limit", "expire", "note", "on_hold_expire_duration"}, "id", MaxUsers)
	if err != nil {
		return nil, err
	}
	proxies := map[int64][]marzbanProxy{}
	if pc := tableCols(ctx, d, "proxies"); pc["user_id"] && pc["settings"] {
		prows, err := selectRows(ctx, d, "proxies", pc, []string{"user_id", "type", "settings"}, "", MaxUsers*8)
		if err != nil {
			return nil, err
		}
		for _, r := range prows {
			raw := toStr(r["settings"])
			if len(raw) > 8192 {
				continue
			}
			var m map[string]any
			if json.Unmarshal([]byte(raw), &m) != nil {
				continue
			}
			p := marzbanProxy{uuid: strings.ToLower(str(m, "id")), password: str(m, "password"), flow: str(m, "flow")}
			if strings.ToLower(toStr(r["type"])) != "trojan" {
				p.password = ""
			}
			proxies[toInt(r["user_id"])] = append(proxies[toInt(r["user_id"])], p)
		}
	}
	data := &Data{Source: SourceMarzban}
	for _, r := range urows {
		if u, ok := marzbanUser(r, proxies[toInt(r["id"])]); ok {
			data.Users = append(data.Users, u)
		}
	}
	if ic := tableCols(ctx, d, "inbounds"); ic["tag"] {
		if rows, err := selectRows(ctx, d, "inbounds", ic, []string{"tag"}, "", MaxInbounds); err == nil {
			for _, r := range rows {
				if t := cleanText(toStr(r["tag"]), 60); t != "" {
					data.Inbounds = append(data.Inbounds, SrcInbound{Name: t, SkipReason: "в базе Marzban хранится только тег; порт и параметры лежат в config.json Xray: укажите этот файл при импорте или создайте подключение в Kitsune"})
				}
			}
		}
	}
	data.Notes = append(data.Notes,
		"Ссылка подписки Marzban строится из токена и не хранится в базе: после переноса у пользователей будут новые ссылки.",
		"Администраторы Marzban и их права не переносятся; ограничения по устройствам в Marzban нет.")
	return data, nil
}

// marzbanProxy – учётные данные пользователя Marzban в одном протоколе.
type marzbanProxy struct{ uuid, password, flow string }

// marzbanUser собирает пользователя из полей Marzban (строка базы или ответ API) и его прокси.
func marzbanUser(r map[string]any, proxies []marzbanProxy) (SrcUser, bool) {
	name := cleanText(toStr(r["username"]), 120)
	if name == "" {
		return SrcUser{}, false
	}
	u := SrcUser{Name: name, Note: cleanText(toStr(r["note"]), maxNoteRunes), Enable: true}
	status := strings.ToLower(toStr(r["status"]))
	if status == "disabled" {
		u.Enable = false
	}
	u.TrafficLimit = toInt(r["data_limit"])
	u.Used = toInt(r["used_traffic"])
	if u.Used < 0 {
		u.Used = 0
	}
	if u.Used > maxTraffic {
		u.Used = maxTraffic
	}
	if u.TrafficLimit < 0 || u.TrafficLimit > maxTraffic {
		u.TrafficLimit = -1
		u.Warnings = append(u.Warnings, "некорректный лимит трафика")
	}
	exp := toInt(r["expire"])
	switch {
	case exp < 0 || exp > maxExpiryMs/1000:
		u.ExpiryMs = -1
		u.Warnings = append(u.Warnings, "некорректный срок")
	case exp > 0:
		u.ExpiryMs = exp * 1000
	case status == "on_hold":
		// Отложенный старт: срок считается от первого подключения.
		if dur := toInt(r["on_hold_expire_duration"]); dur > maxDelayedMs/1000 {
			u.ExpiryMs = -1
			u.Warnings = append(u.Warnings, "отложенный старт дольше 10 лет")
		} else if dur > 0 {
			u.DelayedMs = dur * 1000
			u.Warnings = append(u.Warnings, "отложенный старт: срок будет отсчитан от момента импорта")
		}
	}
	u.Vision = false
	badPass := false
	for _, p := range proxies {
		if u.UUID == "" && p.uuid != "" {
			if pu, err := uuid.Parse(p.uuid); err == nil {
				u.UUID = pu.String()
			}
		}
		if u.Password == "" && validSecret(p.password) {
			u.Password = p.password
			if badPass {
				u.Warnings = dropWarning(u.Warnings, badSecretWarn)
			}
		} else if u.Password == "" && p.password != "" && !badPass {
			badPass = true
			u.Warnings = append(u.Warnings, badSecretWarn)
		}
		if strings.Contains(p.flow, "vision") {
			u.Vision = true
		}
	}
	return u, true

}
