package importer

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"kitsune/internal/proto"
)

var (
	mbpsRe     = regexp.MustCompile(`(?i)^(\d{1,6})\s*(mbps|gbps|kbps)?$`)
	durationRe = regexp.MustCompile(`^[0-9]{1,5}(ms|s|m)$`)
)

const maxMasqueradeBytes = 8192

// quicTLS переносит имя сервера и пути сертификата подключений на QUIC (Hysteria2, TUIC).
// Имя сервера должно остаться прежним, иначе ссылки клиентов перестанут подходить к сертификату.
func quicTLS(stream map[string]any, s *proto.Settings) (warns []string) {
	if name := str(sub(stream, "tlsSettings"), "serverName"); name != "" {
		switch {
		case !hostRe.MatchString(name) || strings.Contains(name, "*"):
			warns = append(warns, "имя сервера (SNI) содержит недопустимые символы: не перенесено")
		case isLocalHost(name):
			warns = append(warns, "имя сервера (SNI) указывало на локальный адрес: не перенесено")
		default:
			s.SNI = name
		}
	}
	return append(warns, tlsFromStream(stream, s)...)
}

// mapHysteria2 переносит подключение Hysteria 2: порт задаёт вызывающий код, здесь пароль обфускации, маскировка,
// ограничения скорости, таймаут UDP, имя сервера и сертификат. Пароли клиентов (auth) переносятся вместе с пользователями.
func mapHysteria2(stream map[string]any) (kind proto.Kind, s proto.Settings, skip string, warns []string) {
	if n := strings.ToLower(str(stream, "network")); n != "" && n != "hysteria" {
		return "", s, "Hysteria с транспортом " + n + " не поддерживается", nil
	}
	if sec := strings.ToLower(str(stream, "security")); sec != "" && sec != "tls" {
		return "", s, "Hysteria без TLS не поддерживается", nil
	}
	hs := sub(stream, "hysteriaSettings")
	if n := toInt(hs["udpIdleTimeout"]); n >= 1 && n <= 86400 {
		s.UDPIdleTimeout = strconv.FormatInt(n, 10)
	}
	fm := sub(stream, "finalmask")
	hop := false
	if arr, ok := fm["udp"].([]any); ok {
		for _, it := range arr {
			m, _ := it.(map[string]any)
			switch strings.ToLower(str(m, "type")) {
			case "salamander":
			case "udphop":
				hop = true
				continue
			default:
				warns = append(warns, "маски UDP, кроме salamander, не переносятся")
				continue
			}
			if p := str(sub(m, "settings"), "password"); validSecret(p) && s.ObfsPassword == "" {
				s.ObfsPassword = p
			} else if s.ObfsPassword == "" {
				warns = append(warns, "пароль обфускации salamander пуст или недопустим: не перенесён, ссылки клиентов придётся обновить")
			}
		}
	}
	qp := sub(fm, "quicParams")
	// порт-хоппинг: в 3x-ui с 3.10 это маска udphop, раньше – quicParams.udpHop
	if len(sub(qp, "udpHop")) > 0 {
		hop = true
	}
	if hop {
		warns = append(warns, "перескок по UDP-портам (udphop) не переносится: подключение будет работать на одном порту")
	}
	for _, l := range []struct {
		key, name string
		dst       *string
	}{{"brutalUp", "отдачи", &s.UpMbps}, {"brutalDown", "загрузки", &s.DownMbps}} {
		v, dropped := mbps(qp[l.key])
		if v > 0 {
			*l.dst = strconv.Itoa(v)
		} else if dropped {
			warns = append(warns, "ограничение скорости "+l.name+" не перенесено: значение не в мегабитах или вне пределов")
		}
	}
	if mq, ok := hs["masquerade"].(map[string]any); ok {
		m, w := masqueradeOf(mq)
		s.Masquerade = m
		if w != "" {
			warns = append(warns, w)
		}
	}
	warns = append(warns, quicTLS(stream, &s)...)
	return proto.Hysteria2, s, "", warns
}

// mbps разбирает ограничение скорости: число или «N mbps» / «N gbps». dropped – значение задано, но перенести его нельзя
// (другие единицы, мусор, больше 100000); 0 и пустое значение – без ограничения, не ошибка.
func mbps(v any) (n int, dropped bool) {
	var t string
	switch x := v.(type) {
	case nil:
		return 0, false
	case string:
		t = strings.TrimSpace(x)
	case float64:
		t = strconv.FormatInt(int64(x), 10)
	default:
		return 0, true
	}
	if t == "" {
		return 0, false
	}
	m := mbpsRe.FindStringSubmatch(t)
	if m == nil {
		return 0, true
	}
	n, _ = strconv.Atoi(m[1])
	switch strings.ToLower(m[2]) {
	case "gbps":
		n *= 1000
	case "kbps":
		return 0, n != 0
	}
	if n > 100000 {
		return 0, true
	}
	return n, false
}

// masqueradeOf превращает маскировку Hysteria 2 в значение Kitsune: адрес сайта или HTML-страница.
// Адрес на локальную машину и страницы, которые Kitsune приняла бы за адрес, не переносятся.
func masqueradeOf(m map[string]any) (val, warn string) {
	switch strings.ToLower(str(m, "type")) {
	case "proxy":
		raw := strings.TrimSpace(str(m, "url"))
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || len(raw) > 300 ||
			!hostRe.MatchString(u.Hostname()) || strings.Contains(u.Hostname(), "*") || isLocalHost(u.Hostname()) {
			return "", "маскировка-прокси указывает на недопустимый или локальный адрес: не перенесена, задайте маскировку вручную"
		}
		for _, r := range raw {
			if r <= 0x20 || r >= 0x7f {
				return "", "маскировка-прокси содержит недопустимые символы: не перенесена, задайте маскировку вручную"
			}
		}
		return raw, ""
	case "string":
		c, _ := m["content"].(string)
		low := strings.ToLower(strings.TrimSpace(c))
		switch {
		case c == "":
			return "", ""
		case len(c) > maxMasqueradeBytes || !utf8.ValidString(c):
			return "", "страница маскировки слишком большая: не перенесена, задайте маскировку вручную"
		case strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://"):
			return "", "страница маскировки начинается с адреса: не перенесена, задайте маскировку вручную"
		}
		return c, ""
	case "":
		return "", ""
	}
	return "", "маскировка этого вида не переносится: задайте маскировку вручную"
}

// mapTUIC переносит подключение TUIC: режимы, таймауты и сертификат. Ключи клиентов (uuid и пароль) идут вместе с пользователями.
func mapTUIC(st, stream map[string]any) (kind proto.Kind, s proto.Settings, skip string, warns []string) {
	if len(sub(stream, "tlsSettings")) == 0 {
		// Формат sing-box: параметры TLS лежат в самих настройках.
		if t := sub(st, "tls"); len(t) > 0 {
			ts := map[string]any{}
			if n := str(t, "server_name"); n != "" {
				ts["serverName"] = n
			}
			if c, k := str(t, "certificate_path"), str(t, "key_path"); c != "" && k != "" {
				ts["certificates"] = []any{map[string]any{"certificateFile": c, "keyFile": k}}
			}
			stream = map[string]any{"tlsSettings": ts}
		}
	}
	switch v := str(st, "congestion_control"); v {
	case "bbr", "cubic", "new_reno":
		s.Congestion = v
	}
	switch v := str(st, "udp_relay_mode"); v {
	case "native", "quic":
		s.UDPRelayMode = v
	}
	if toBool(st["zero_rtt_handshake"], false) {
		s.ZeroRTT = "true"
	}
	for _, d := range []struct {
		key, name string
		dst       *string
	}{{"heartbeat", "heartbeat", &s.Heartbeat}, {"auth_timeout", "auth_timeout", &s.AuthTimeout}} {
		if v := str(st, d.key); durationRe.MatchString(v) {
			*d.dst = v
		} else if st[d.key] != nil && st[d.key] != "" {
			warns = append(warns, d.name+" не перенесён: нужна запись с единицей (например, 10s)")
		}
	}
	warns = append(warns, quicTLS(stream, &s)...)
	return proto.TUIC, s, "", warns
}
