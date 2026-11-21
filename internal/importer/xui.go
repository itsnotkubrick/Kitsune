package importer

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"

	"kitsune/internal/proto"
)

var (
	subIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	hostRe  = regexp.MustCompile(`^(?:[A-Za-z0-9*-]*[A-Za-z0-9][A-Za-z0-9*-]*\.)*[A-Za-z0-9*-]*[A-Za-z0-9][A-Za-z0-9*-]*\.?$`) // метки непустые, в каждой есть буква или цифра; длину смотрит validHost
	sidRe   = regexp.MustCompile(`^([0-9a-fA-F]{2}){0,8}$`)
	pathRe  = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,198}$`)
	svcRe   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
)

type xuiClient struct {
	email, subID, id, password, flow, comment string
	limitIP, totalGB, expiry                  int64
	enable                                    bool
}

// Read3XUI читает базу 3x-ui: подключения, клиентов (старый формат – из JSON подключений, новый – из таблицы clients)
// и использованный трафик из client_traffics.
func Read3XUI(path string, opts ...ReadOpt) (*Data, error) {
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()
	d, closeDB, err := openCopy(ctx, path, newReadCfg(opts))
	if err != nil {
		return nil, err
	}
	defer closeDB()
	return read3XUI(ctx, d)
}

func read3XUI(ctx context.Context, d *sql.DB) (*Data, error) {
	ib := tableCols(ctx, d, "inbounds")
	for _, c := range []string{"id", "port", "protocol", "settings"} {
		if !ib[c] {
			return nil, errors.New("это не база 3x-ui: нет таблицы подключений нужной схемы")
		}
	}
	irows, err := selectRows(ctx, d, "inbounds", ib, []string{"id", "remark", "tag", "enable", "listen", "node_id", "port", "protocol", "settings", "stream_settings"}, "id", MaxInbounds)
	if err != nil {
		return nil, err
	}
	data := &Data{Source: Source3XUI}
	used := map[string]int64{}
	if ct := tableCols(ctx, d, "client_traffics"); ct["email"] {
		trs, err := selectRows(ctx, d, "client_traffics", ct, []string{"email", "up", "down"}, "", MaxUsers*4)
		if err != nil {
			return nil, err
		}
		for _, r := range trs {
			used[strings.ToLower(strings.TrimSpace(toStr(r["email"])))] += clampTraffic(toInt(r["up"])) + clampTraffic(toInt(r["down"]))
		}
	}

	var clients []xuiClient
	protoOf := map[string]string{} // email -> протокол подключения (для выбора uuid и пароля)
	for _, r := range irows {
		in, cl := mapXUIInbound(r)
		data.Inbounds = append(data.Inbounds, in)
		for _, c := range cl {
			clients = append(clients, c)
			protoOf[strings.ToLower(c.email)] = in.Protocol
		}
	}
	// Новая схема 3x-ui: клиенты в отдельной таблице.
	if cc := tableCols(ctx, d, "clients"); cc["email"] && cc["uuid"] {
		rows, err := selectRows(ctx, d, "clients", cc, []string{"email", "sub_id", "uuid", "password", "auth", "flow", "limit_ip", "total_gb", "expiry_time", "enable", "comment"}, "id", MaxUsers*4)
		if err != nil {
			return nil, err
		}
		if len(rows) > 0 {
			clients = clients[:0]
			dropped := 0
			for _, r := range rows {
				c := xuiClient{
					email: toStr(r["email"]), subID: toStr(r["sub_id"]), id: toStr(r["uuid"]), password: toStr(r["password"]),
					flow: toStr(r["flow"]), comment: toStr(r["comment"]), limitIP: toInt(r["limit_ip"]), totalGB: toInt(r["total_gb"]),
					expiry: toInt(r["expiry_time"]), enable: toBool(r["enable"], true),
				}
				// Пароль переносится только у клиентов Trojan, Hysteria2 и TUIC (у Shadowsocks это ключ).
				pr := protoOf[strings.ToLower(c.email)]
				if (pr == "hysteria" || pr == "hysteria2") && toStr(r["auth"]) != "" {
					c.password = toStr(r["auth"])
				}
				if !passwordProto(pr) {
					if c.password != "" {
						dropped++
					}
					c.password = ""
				}
				clients = append(clients, c)
			}
			if dropped > 0 {
				data.Notes = append(data.Notes, fmt.Sprintf("Пароли переносятся только у клиентов Trojan, Hysteria2 и TUIC; у %d клиентов других протоколов пароль не перенесён.", dropped))
			}
		}
	}
	data.Users = groupXUIClients(clients, used, &data.Notes)
	if len(data.Users) > MaxUsers {
		return nil, fmt.Errorf("пользователей больше %d", MaxUsers)
	}
	data.Notes = append(data.Notes, "Учётные записи администраторов 3x-ui и настройки панели не переносятся.")
	return data, nil
}

// passwordProto – протоколы, у клиентов которых пароль переносится в пароль пользователя Kitsune
// (у Shadowsocks это ключ, он не переносится).
func passwordProto(p string) bool {
	return p == "trojan" || p == "hysteria" || p == "hysteria2" || p == "tuic"
}

func clampTraffic(v int64) int64 {
	if v < 0 {
		return 0
	}
	if v > maxTraffic {
		return maxTraffic
	}
	return v
}

// groupXUIClients склеивает клиентов с одним subId (один человек в нескольких подключениях) в одного пользователя.
func groupXUIClients(cl []xuiClient, used map[string]int64, notes *[]string) []SrcUser {
	type grp struct {
		u        SrcUser
		seen     map[string]bool
		tvals    map[int64]bool // разные значения лимита трафика у клиентов группы
		evals    map[int64]bool // разные значения срока
		unlimE   bool           // у кого-то из группы срока нет
		passDiff bool           // у клиентов группы разные пароли
		badPass  bool           // пароль не перенесён: пробел, управляющие знаки или длиннее 128
		uuidDiff bool           // и разные UUID
	}
	var order []string
	groups := map[string]*grp{}
	for _, c := range cl {
		email := cleanText(c.email, 120)
		if email == "" {
			continue
		}
		key := "e:" + strings.ToLower(email)
		sub := strings.TrimSpace(c.subID)
		if subIDRe.MatchString(sub) {
			key = "s:" + sub
		}
		g := groups[key]
		if g == nil {
			g = &grp{seen: map[string]bool{}, tvals: map[int64]bool{}, evals: map[int64]bool{}}
			g.u = SrcUser{Name: email, Enable: false, Vision: false}
			if subIDRe.MatchString(sub) {
				g.u.SubID = sub
			} else if sub != "" {
				g.u.Warnings = append(g.u.Warnings, "subId содержит недопустимые символы: ссылка подписки будет создана заново")
			}
			groups[key] = g
			order = append(order, key)
		}
		le := strings.ToLower(email)
		if g.seen[le] {
			continue
		}
		g.seen[le] = true
		u := &g.u
		u.Used += used[le]
		if u.Used > maxTraffic {
			u.Used = maxTraffic
		}
		if c.enable {
			u.Enable = true
		}
		if strings.Contains(c.flow, "vision") {
			u.Vision = true
		}
		if id := strings.ToLower(strings.TrimSpace(c.id)); u.UUID == "" && id != "" {
			if p, err := uuid.Parse(id); err == nil {
				u.UUID = p.String() // Xray принимает только обычную запись: urn:uuid:, {…} и без дефисов приводим к ней
			} else if len(id) < 80 {
				u.Warnings = append(u.Warnings, "идентификатор клиента не похож на UUID: будет создан новый")
			}
		} else if id != "" && u.UUID != "" && !g.uuidDiff {
			if p, err := uuid.Parse(id); err == nil && p.String() != u.UUID {
				g.uuidDiff = true
				u.Warnings = append(u.Warnings, "в разных подключениях у клиента разные UUID: перенесён первый, ссылки остальных придётся обновить")
			}
		}
		if u.Password == "" && validSecret(c.password) {
			u.Password = c.password
			if g.badPass {
				u.Warnings = dropWarning(u.Warnings, badSecretWarn) // валидный пароль нашёлся в другом подключении
			}
		} else if u.Password == "" && c.password != "" && !g.badPass {
			g.badPass = true
			u.Warnings = append(u.Warnings, badSecretWarn)
		} else if u.Password != "" && c.password != "" && c.password != u.Password && !g.passDiff {
			g.passDiff = true
			u.Warnings = append(u.Warnings, "в разных подключениях у клиента разные пароли: перенесён первый, ссылки остальных придётся обновить")
		}
		if n := cleanText(c.comment, maxNoteRunes); u.Note == "" {
			u.Note = n
		}
		if int(c.limitIP) > u.IPLimit {
			u.IPLimit = int(min64(c.limitIP, maxIPLimit))
		}
		switch {
		case c.totalGB < 0 || c.totalGB > maxTraffic:
			u.Warnings = append(u.Warnings, "некорректный лимит трафика")
			u.TrafficLimit = -1
		case len(g.seen) == 1:
			u.TrafficLimit = c.totalGB
		case u.TrafficLimit < 0:
		case u.TrafficLimit == 0 || c.totalGB == 0:
			u.TrafficLimit = 0 // безлимит сильнее любого лимита: клиент не должен молча стать ограниченным
		case c.totalGB > u.TrafficLimit:
			u.TrafficLimit = c.totalGB
		}
		g.tvals[c.totalGB] = true
		g.evals[c.expiry] = true
		switch {
		case c.expiry > maxExpiryMs || c.expiry < -maxExpiryMs:
			u.Warnings = append(u.Warnings, "некорректный срок")
			u.ExpiryMs = -1
		case c.expiry < -maxDelayedMs:
			u.Warnings = append(u.Warnings, "отложенный старт дольше 10 лет")
			u.ExpiryMs = -1
		case c.expiry < 0:
			// Отложенный старт: -мс = длительность после первого подключения.
			if -c.expiry > u.DelayedMs {
				u.DelayedMs = -c.expiry
			}
		case c.expiry == 0:
			g.unlimE = true
		case u.ExpiryMs >= 0 && c.expiry > u.ExpiryMs:
			u.ExpiryMs = c.expiry
		}
	}
	out := make([]SrcUser, 0, len(order))
	for _, k := range order {
		g := groups[k]
		if g.unlimE && g.u.ExpiryMs >= 0 {
			g.u.ExpiryMs, g.u.DelayedMs = 0, 0 // бессрочный клиент в группе: срок не ставится
		}
		if len(g.tvals) > 1 || len(g.evals) > 1 {
			g.u.Warnings = append(g.u.Warnings, "у клиентов одного subId разные лимиты или сроки: безлимит сильнее остальных, иначе взяты наибольшие")
		}
		if len(g.seen) > 1 {
			g.u.Warnings = append(g.u.Warnings, fmt.Sprintf("объединено клиентов с одним subId: %d", len(g.seen)))
		}
		if g.u.ExpiryMs == 0 && g.u.DelayedMs > 0 {
			g.u.Warnings = append(g.u.Warnings, "отложенный старт: срок будет отсчитан от момента импорта")
		}
		out = append(out, g.u)
	}
	return out
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// badSecretWarn – причина, по которой пароль клиента заменён новым (значение пароля в текст не попадает).
const badSecretWarn = "пароль клиента не перенесён: в нём пробел, недопустимые знаки или он длиннее 128 знаков; будет создан новый, ссылка клиента изменится"

// dropWarning убирает предупреждение с точным текстом msg.
func dropWarning(ws []string, msg string) []string {
	out := ws[:0]
	for _, w := range ws {
		if w != msg {
			out = append(out, w)
		}
	}
	return out
}

func validSecret(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

// mapXUIInbound переводит строку inbounds в подключение Kitsune (или причину пропуска) и список клиентов из JSON.
func mapXUIInbound(r map[string]any) (SrcInbound, []xuiClient) {
	in := SrcInbound{
		Name:     cleanText(toStr(r["remark"]), 60),
		Port:     int(toInt(r["port"])),
		Protocol: strings.ToLower(cleanText(toStr(r["protocol"]), 30)),
		Enable:   toBool(r["enable"], true),
	}
	if in.Name == "" {
		in.Name = cleanText(toStr(r["tag"]), 60)
	}
	if in.Name == "" {
		in.Name = fmt.Sprintf("%s-%d", in.Protocol, in.Port)
	}
	settingsRaw, streamRaw := toStr(r["settings"]), toStr(r["stream_settings"])
	if len(settingsRaw) > maxJSONBytes || len(streamRaw) > maxJSONBytes {
		in.SkipReason = "пропущено: настройки больше 1 МБ"
		if n := strings.Count(settingsRaw, `"email"`); len(settingsRaw) > maxJSONBytes && n > 0 {
			in.SkipReason += fmt.Sprintf(" (≈ %d клиентов)", n)
		}
		return in, nil
	}
	var st, stream map[string]any
	_ = json.Unmarshal([]byte(settingsRaw), &st)
	_ = json.Unmarshal([]byte(streamRaw), &stream)
	if st == nil {
		st = map[string]any{}
	}
	if stream == nil {
		stream = map[string]any{}
	}
	var clients []xuiClient
	list, ok := st["clients"].([]any)
	if !ok && in.Protocol == "tuic" {
		list, _ = st["users"].([]any)
	}
	for _, it := range list {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		c := xuiClient{
			email: toStr(m["email"]), subID: toStr(m["subId"]), id: toStr(m["id"]), password: toStr(m["password"]),
			flow: toStr(m["flow"]), comment: toStr(m["comment"]), limitIP: toInt(m["limitIp"]), totalGB: toInt(m["totalGB"]),
			expiry: toInt(m["expiryTime"]), enable: toBool(m["enable"], true),
		}
		if c.id == "" {
			c.id = toStr(m["uuid"])
		}
		if c.email == "" {
			c.email = toStr(m["name"])
		}
		if in.Protocol == "hysteria" || in.Protocol == "hysteria2" {
			if a := toStr(m["auth"]); a != "" {
				c.password = a // у Hysteria2 пароль клиента лежит в поле auth
			}
		}
		if !passwordProto(in.Protocol) {
			c.password = "" // пароль Shadowsocks и других протоколов не переносится
		}
		clients = append(clients, c)
	}
	if in.Port < 1 || in.Port > 65535 {
		in.SkipReason = "некорректный порт"
		return in, clients
	}
	if l := strings.TrimSpace(toStr(r["listen"])); l != "" && l != "0.0.0.0" && l != "::" && l != "[::]" {
		in.SkipReason = "подключение слушает только свой адрес (внутреннее, например для перенаправления): наружу не открывается, не переносится"
		return in, clients
	}
	if toInt(r["node_id"]) != 0 {
		in.SkipReason = "подключение работает на другом сервере (ноде) 3x-ui: не переносится"
		return in, clients
	}
	in.Kind, in.Settings, in.SkipReason, in.Warnings = mapXUIKind(in.Protocol, st, stream)
	return in, clients
}

func sub(m map[string]any, key string) map[string]any {
	v, _ := m[key].(map[string]any)
	if v == nil {
		return map[string]any{}
	}
	return v
}

func str(m map[string]any, key string) string {
	switch t := m[key].(type) {
	case string:
		return cleanText(t, 300)
	case float64:
		return fmt.Sprint(int64(t))
	}
	return ""
}

func firstStr(m map[string]any, key string) string {
	if arr, ok := m[key].([]any); ok && len(arr) > 0 {
		if s, ok := arr[0].(string); ok {
			return cleanText(s, 253)
		}
	}
	return ""
}

func mapXUIKind(protocol string, st, stream map[string]any) (kind proto.Kind, s proto.Settings, skip string, warns []string) {
	network := strings.ToLower(str(stream, "network"))
	security := strings.ToLower(str(stream, "security"))
	if network == "" {
		network = "tcp"
	}
	switch protocol {
	case "vless":
		switch {
		case security == "reality" && network == "tcp":
			kind = proto.VlessReality
		case security == "reality" && (network == "xhttp" || network == "splithttp"):
			kind = proto.VlessXHTTP
		case security == "tls" && network == "ws":
			kind = proto.VlessWS
		default:
			return "", s, fmt.Sprintf("VLESS с транспортом %s и защитой %s не поддерживается", network, orNone(security)), nil
		}
	case "vmess":
		if security != "tls" || network != "ws" {
			return "", s, fmt.Sprintf("VMess с транспортом %s и защитой %s не поддерживается (нужен WebSocket с TLS)", network, orNone(security)), nil
		}
		kind = proto.VmessWS
	case "trojan":
		if security != "tls" || network != "grpc" {
			return "", s, fmt.Sprintf("Trojan с транспортом %s и защитой %s не поддерживается (нужен gRPC с TLS)", network, orNone(security)), nil
		}
		kind = proto.TrojanGRPC
	case "shadowsocks":
		method := str(st, "method")
		if !strings.HasPrefix(method, "2022-") || (method != "2022-blake3-aes-128-gcm" && method != "2022-blake3-aes-256-gcm" && method != "2022-blake3-chacha20-poly1305") {
			return "", s, "Shadowsocks со старым методом шифрования не поддерживается (нужен 2022)", nil
		}
		key := str(st, "password")
		raw, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(raw) != proto.SSKeySize(method) {
			return "", s, "ключ сервера Shadowsocks не подходит к методу", nil
		}
		s.Method, s.ServerKey = method, key
		if n := str(st, "network"); n == "tcp" || n == "udp" || n == "tcp,udp" {
			s.Network = n
		}
		warns = append(warns, "ключи пользователей Shadowsocks не переносятся: у пользователей новые ключи")
		return proto.SS2022, s, "", warns
	case "hysteria", "hysteria2":
		hs := sub(stream, "hysteriaSettings")
		ver := toInt(st["version"])
		if ver == 0 {
			ver = toInt(hs["version"])
		}
		if protocol == "hysteria" && ver != 2 {
			return "", s, "Hysteria первой версии не переносится (нужна Hysteria 2)", nil
		}
		return mapHysteria2(stream)
	case "tuic":
		return mapTUIC(st, stream)
	case "wireguard", "amneziawg", "mtproto", "masque", "xdrive", "tun":
		return "", s, "протокол " + protocol + " не переносится, создайте подключение в Kitsune", nil
	case "http", "mixed", "socks", "tunnel", "dokodemo-door":
		return "", s, "служебный протокол " + protocol + " не переносится", nil
	default:
		return "", s, "неизвестный протокол", nil
	}

	switch kind {
	case proto.VlessReality, proto.VlessXHTTP:
		rs := sub(stream, "realitySettings")
		in := sub(rs, "settings")
		s.SNI = firstStr(rs, "serverNames")
		if s.SNI == "" {
			s.SNI = str(in, "serverName")
		}
		if s.SNI == "" {
			return "", s, "не задано имя сайта маскировки", nil
		}
		if !validHost(s.SNI) || strings.Contains(s.SNI, "*") {
			return "", s, "недопустимое имя сайта маскировки", nil
		}
		if isLocalHost(s.SNI) {
			return "", s, "имя сайта маскировки указывает на локальный адрес", nil
		}
		t := str(rs, "target") // новые версии 3x-ui пишут target, старые – dest
		if t == "" {
			t = str(rs, "dest")
		}
		if t != "" {
			tv, w := checkTarget(t)
			s.Target = tv
			if w != "" {
				warns = append(warns, w)
			}
		} else {
			warns = append(warns, "адрес сайта маскировки (target) в источнике не задан: будет использовано имя сайта с портом 443")
		}
		s.PrivateKey = str(rs, "privateKey")
		s.PublicKey = str(in, "publicKey")
		if raw, err := base64.RawURLEncoding.DecodeString(s.PrivateKey); err != nil || len(raw) != 32 {
			s.PrivateKey, s.PublicKey = "", ""
			warns = append(warns, "ключей REALITY нет: созданы новые, ссылки клиентов придётся обновить")
		} else {
			pub, _ := curve25519.X25519(raw, curve25519.Basepoint)
			calc := base64.RawURLEncoding.EncodeToString(pub)
			if s.PublicKey != "" && s.PublicKey != calc {
				warns = append(warns, "публичный ключ REALITY не совпал с закрытым: взят вычисленный, ссылки клиентов могут измениться")
			}
			s.PublicKey = calc
		}
		var sids []string
		if arr, ok := rs["shortIds"].([]any); ok {
			for _, v := range arr {
				if x, ok := v.(string); ok && sidRe.MatchString(x) && x != "" {
					sids = append(sids, x)
				}
			}
		}
		s.ShortIDs = strings.Join(sids, ",")
		if fp := str(in, "fingerprint"); fp != "" && svcRe.MatchString(fp) {
			s.Fingerprint = fp
		}
		if kind == proto.VlessXHTTP {
			xs := sub(stream, "xhttpSettings")
			if len(xs) == 0 {
				xs = sub(stream, "splithttpSettings")
			}
			if p := str(xs, "path"); pathRe.MatchString(p) {
				s.Path = p
			}
			if m := str(xs, "mode"); m == "auto" || m == "packet-up" || m == "stream-up" || m == "stream-one" {
				s.Mode = m
			}
		}
	case proto.VlessWS, proto.VmessWS:
		ws := sub(stream, "wsSettings")
		if p := str(ws, "path"); pathRe.MatchString(p) {
			s.Path = p
		}
		h := str(ws, "host")
		if h == "" {
			h = str(sub(ws, "headers"), "Host")
		}
		if h != "" && validHost(h) {
			s.Host = h
		}
		warns = append(warns, tlsFromStream(stream, &s)...)
	case proto.TrojanGRPC:
		g := sub(stream, "grpcSettings")
		if n := str(g, "serviceName"); svcRe.MatchString(n) {
			s.ServiceName = n
		}
		warns = append(warns, tlsFromStream(stream, &s)...)
	}
	return kind, s, "", warns
}

// validHost: имя из букв, цифр, дефисов и точек, без пустых меток, до 253 знаков.
func validHost(h string) bool { return len(h) <= 253 && hostRe.MatchString(h) }

// checkTarget проверяет адрес сайта маскировки host[:port]. Пустой результат – значение по умолчанию (SNI:443);
// предупреждение объясняет, почему адрес не перенесён.
func checkTarget(t string) (string, string) {
	host, port := t, ""
	if h, p, err := net.SplitHostPort(t); err == nil {
		host, port = h, p
	} else if strings.Count(t, ":") == 1 {
		i := strings.Index(t, ":")
		host, port = t[:i], t[i+1:]
	}
	if strings.HasSuffix(t, ":") { // пустой порт после двоеточия
		return "", "адрес сайта маскировки (target) с неверным портом не перенесён: будет использован адрес по умолчанию"
	}
	if port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || port != strconv.Itoa(n) {
			return "", "адрес сайта маскировки (target) с неверным портом не перенесён: будет использован адрес по умолчанию"
		}
	}
	host = strings.TrimRight(host, ".")
	if isLocalHost(host) {
		return "", localTargetWarn
	}
	if !validHost(host) {
		return "", "адрес сайта маскировки (target) не перенесён"
	}
	return t, ""
}

// isLocalHost сообщает, что имя или адрес указывает на саму машину или закрытую сеть:
// localhost и его варианты, частные, loopback, link-local, CGNAT (100.64/10), 198.18/15, 0/8, multicast, broadcast.
func isLocalHost(host string) bool {
	host = strings.TrimRight(host, ".")
	if ip := localNumericIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
			return true
		}
		if v4 := ip.To4(); v4 != nil {
			switch {
			case v4[0] == 0, v4[0] == 100 && v4[1]&0xc0 == 64, v4[0] == 198 && v4[1]&0xfe == 18, v4.Equal(net.IPv4bcast):
				return true
			}
		}
		return false
	}
	lh := strings.ToLower(host)
	switch lh {
	case "localhost", "localhost6", "ip6-localhost", "ip6-loopback", "localhost.localdomain", "localhost6.localdomain6":
		return true
	}
	for _, suf := range []string{".localhost", ".local", ".internal", ".localdomain", ".home.arpa"} {
		if strings.HasSuffix(lh, suf) {
			return true
		}
	}
	return false
}

// localNumericIP разбирает адрес, включая короткие формы inet_aton (2130706433, 0x7f.1, 0177.0.0.1), которые понимает резолвер.
// Не адрес – nil.
func localNumericIP(h string) net.IP {
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
		return ip
	}
	parts := strings.Split(h, ".")
	if len(parts) > 4 {
		return nil
	}
	var v uint64
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 0, 32)
		if err != nil {
			return nil
		}
		if i < len(parts)-1 {
			if n > 255 {
				return nil
			}
			v |= n << (8 * uint(3-i))
		} else {
			if n >= uint64(1)<<(8*uint(4-i)) {
				return nil
			}
			v |= n
		}
	}
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

const localTargetWarn = "target указывал на локальный адрес: не перенесён, будет использован адрес по умолчанию"

func orNone(s string) string {
	if s == "" || s == "none" {
		return "без шифрования"
	}
	return s
}

// tlsFromStream берёт пути сертификата, если они заданы; иначе подключение получит самоподписанный.
func tlsFromStream(stream map[string]any, s *proto.Settings) (warns []string) {
	ts := sub(stream, "tlsSettings")
	if certs, ok := ts["certificates"].([]any); ok && len(certs) > 0 {
		if c, ok := certs[0].(map[string]any); ok {
			cf, kf := str(c, "certificateFile"), str(c, "keyFile")
			if strings.HasPrefix(cf, "/") && strings.HasPrefix(kf, "/") && !strings.Contains(cf+kf, "..") {
				s.CertMode, s.CertFile, s.KeyFile = "custom", cf, kf
				return append(warns, "файлы сертификата указаны по прежним путям: проверьте, что они есть на этом сервере")
			}
		}
	}
	s.CertMode = "self"
	return append(warns, "сертификат не перенесён: выпущен самоподписанный, замените в настройках подключения")
}
