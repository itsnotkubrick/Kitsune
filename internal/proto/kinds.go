// Package proto описывает протоколы панели: каталог типов подключений, их параметры, конфиги ядер,
// ссылки для клиентов и профили для Clash/sing-box.
package proto

// Kind – идентификатор типа подключения.
type Kind string

const (
	VlessReality Kind = "vless-reality"
	VlessXHTTP   Kind = "vless-xhttp"
	VlessWS      Kind = "vless-ws"
	TrojanGRPC   Kind = "trojan-grpc"
	VmessWS      Kind = "vmess-ws"
	SS2022       Kind = "ss2022"
	Hysteria2    Kind = "hysteria2"
	TUIC         Kind = "tuic"
	AWG          Kind = "awg"
	AWG3         Kind = "awg3"
	MTProto      Kind = "mtproto"
	Naive        Kind = "naive"
	Mieru        Kind = "mieru"
	Masque       Kind = "masque"
)

// Ядра, которые обслуживают подключения.
const (
	CoreXray    = "xray"
	CoreSingbox = "singbox"
	CoreMita    = "mita"
	CoreMTG     = "mtg"
	CoreAWG     = "awg"
	// CoreMasque – отдельный экземпляр sing-box (1.15 и новее, в том числе предрелизы): MASQUE есть только там, а основной sing-box
	// остаётся на проверенной версии для TUIC и NaiveProxy.
	CoreMasque = "masque"
)

type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Field – настраиваемый параметр подключения; по нему интерфейс рисует форму.
type Field struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Type    string   `json:"type"` // text | number | select | bool | textarea
	Default string   `json:"default,omitempty"`
	Options []Option `json:"options,omitempty"`
	Help    string   `json:"help,omitempty"`
	Adv     bool     `json:"adv"` // тонкая настройка: поле показывается ниже основных
}

type Info struct {
	ID          Kind    `json:"id"`
	Title       string  `json:"title"`
	Tag         string  `json:"tag"` // имя подключения по умолчанию
	Core        string  `json:"core"`
	Net         string  `json:"net"` // tcp | udp | both
	DefaultPort int     `json:"default_port"`
	TLS         bool    `json:"tls"`
	Desc        string  `json:"desc"`
	Fields      []Field `json:"fields"`
}

func opts(pairs ...string) []Option {
	var o []Option
	for i := 0; i+1 < len(pairs); i += 2 {
		o = append(o, Option{pairs[i], pairs[i+1]})
	}
	return o
}

var fingerprints = opts("chrome", "chrome", "firefox", "firefox", "safari", "safari", "ios", "ios", "android", "android",
	"edge", "edge", "360", "360", "qq", "qq", "random", "random", "randomized", "randomized")

var commonAdv = []Field{
	{Key: "listen", Label: "Адрес прослушивания", Type: "text", Help: "Пусто – все интерфейсы. 127.0.0.1 – только локально (для режима «всё на 443»)", Adv: true},
	{Key: "sniffing", Label: "Sniffing (определение протокола трафика)", Type: "bool", Default: "true", Adv: true},
	{Key: "route_only", Label: "Sniffing только для маршрутизации", Type: "bool", Default: "false", Adv: true, Help: "Домен из sniffing используется только для правил, адрес назначения не подменяется"},
	{Key: "xray_patch", Label: "Свой JSON (вливается в подключение Xray)", Type: "textarea", Help: "Объект JSON, который объединяется с готовым подключением. Для тонкой настройки: например {\"streamSettings\":{\"sockopt\":{\"tcpFastOpen\":true}}}", Adv: true},
	{Key: "external_host", Label: "Адрес для ссылок клиентов", Type: "text", Help: "Пусто – адрес панели. Нужен, если клиенты ходят через другой домен или CDN", Adv: true},
	{Key: "external_port", Label: "Порт для ссылок клиентов", Type: "number", Help: "Пусто – порт подключения (например 443 при проксировании nginx)", Adv: true},
}

var tlsFields = []Field{
	{Key: "sni", Label: "SNI / домен сертификата", Type: "text", Help: "Пусто – адрес панели. Должен совпадать с сертификатом"},
	{Key: "cert_mode", Label: "Сертификат", Type: "select", Default: "self", Options: opts("self", "Самоподписанный (панель выпустит сама)", "acme", "Let's Encrypt (нужны домен в поле SNI и порт 80)", "custom", "Свои файлы (укажите пути ниже)"), Help: "Без домена остаётся самоподписанный: на проверке он отличается от обычного сайта"},
	{Key: "cert_file", Label: "Файл сертификата (.crt / fullchain.pem)", Type: "text", Adv: true},
	{Key: "key_file", Label: "Файл ключа (.key / privkey.pem)", Type: "text", Adv: true},
	{Key: "fingerprint", Label: "TLS-отпечаток клиента (uTLS)", Type: "select", Default: "chrome", Options: fingerprints, Adv: true},
	{Key: "min_version", Label: "Минимальная версия TLS", Type: "select", Default: "", Options: opts("", "по умолчанию", "1.2", "1.2", "1.3", "1.3"), Adv: true},
}

var realityFields = []Field{
	{Key: "sni", Label: "Сайт маскировки (SNI)", Type: "text", Default: "dl.google.com", Help: "Сервер, под который маскируется подключение. Нужен сайт с TLS 1.3 и HTTP/2"},
	{Key: "target", Label: "Целевой адрес (dest)", Type: "text", Help: "host:port, куда уходит чужой трафик. Пусто – SNI:443", Adv: true},
	{Key: "fingerprint", Label: "TLS-отпечаток клиента (uTLS)", Type: "select", Default: "chrome", Options: fingerprints, Adv: true},
	{Key: "short_ids", Label: "Short ID (через запятую)", Type: "text", Help: "До 16 hex-символов; несколько значений через запятую", Adv: true},
	{Key: "spider_x", Label: "SpiderX", Type: "text", Default: "/", Adv: true},
	{Key: "xver", Label: "PROXY protocol при передаче на dest (xver)", Type: "select", Default: "0", Options: opts("0", "выкл", "1", "v1", "2", "v2"), Adv: true},
	{Key: "max_time_diff", Label: "Допустимая разница времени, мс", Type: "number", Help: "0 – не проверять", Adv: true},
	{Key: "accept_proxy", Label: "Принимать PROXY protocol", Type: "bool", Help: "Включайте, если перед подключением стоит nginx/haproxy", Adv: true},
}

// Catalog – все типы подключений панели.
var Catalog = []Info{
	{ID: VlessReality, Tag: "REALITY", Title: "VLESS + REALITY", Core: CoreXray, Net: "tcp", DefaultPort: 443,
		Desc: "Основной протокол: маскируется под настоящий сайт, не требует домена и сертификата.",
		Fields: append(append([]Field{}, realityFields...),
			Field{Key: "flow", Label: "Flow", Type: "select", Default: "xtls-rprx-vision", Options: opts("xtls-rprx-vision", "xtls-rprx-vision", "none", "нет"), Adv: true, Help: "Vision ускоряет и защищает от детекта TLS-в-TLS. Отключается и на уровне пользователя"})},
	{ID: VlessXHTTP, Tag: "XHTTP", Title: "VLESS + XHTTP + REALITY", Core: CoreXray, Net: "tcp", DefaultPort: 8443,
		Desc: "XHTTP поверх REALITY: хорошо проходит через CDN-подобные фильтры, поддерживает HTTP/2 и HTTP/3-режимы.",
		Fields: append(append([]Field{}, realityFields...),
			Field{Key: "path", Label: "Путь", Type: "text", Help: "Пусто – случайный"},
			Field{Key: "mode", Label: "Режим XHTTP", Type: "select", Default: "auto", Options: opts("auto", "auto", "packet-up", "packet-up", "stream-up", "stream-up", "stream-one", "stream-one"), Adv: true},
			Field{Key: "host", Label: "Host (заголовок)", Type: "text", Adv: true},
			Field{Key: "no_sse_header", Label: "Отключить SSE-заголовок", Type: "bool", Adv: true})},
	{ID: VlessWS, Tag: "VLESS-WS", Title: "VLESS + WebSocket + TLS", Core: CoreXray, Net: "tcp", DefaultPort: 2053, TLS: true,
		Desc: "Классика для работы через CDN (Cloudflare). Нужен TLS-сертификат.",
		Fields: append(append([]Field{},
			Field{Key: "path", Label: "Путь WebSocket", Type: "text", Help: "Пусто – случайный"},
			Field{Key: "host", Label: "Host (заголовок)", Type: "text", Adv: true}), tlsFields...)},
	{ID: TrojanGRPC, Tag: "Trojan-gRPC", Title: "Trojan + gRPC + TLS", Core: CoreXray, Net: "tcp", DefaultPort: 2083, TLS: true,
		Desc: "Trojan поверх gRPC: выглядит как обычный HTTP/2-сервис.",
		Fields: append(append([]Field{},
			Field{Key: "service_name", Label: "Имя сервиса gRPC", Type: "text", Help: "Пусто – случайное"},
			Field{Key: "authority", Label: "Authority", Type: "text", Adv: true},
			Field{Key: "multi_mode", Label: "Multi mode", Type: "bool", Adv: true}), tlsFields...)},
	{ID: VmessWS, Tag: "VMess-WS", Title: "VMess + WebSocket + TLS", Core: CoreXray, Net: "tcp", DefaultPort: 2087, TLS: true,
		Desc: "Для старых клиентов, которым нужен VMess. Нужен TLS-сертификат.",
		Fields: append(append([]Field{},
			Field{Key: "path", Label: "Путь WebSocket", Type: "text", Help: "Пусто – случайный"},
			Field{Key: "host", Label: "Host (заголовок)", Type: "text", Adv: true}), tlsFields...)},
	{ID: SS2022, Tag: "Shadowsocks", Title: "Shadowsocks 2022", Core: CoreXray, Net: "both", DefaultPort: 8388,
		Desc: "Современный Shadowsocks с отдельным ключом на каждого пользователя.",
		Fields: []Field{
			{Key: "method", Label: "Шифр", Type: "select", Default: "2022-blake3-aes-128-gcm", Options: opts(
				"2022-blake3-aes-128-gcm", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-aes-256-gcm",
				"2022-blake3-chacha20-poly1305", "2022-blake3-chacha20-poly1305"), Adv: true},
			{Key: "network", Label: "Сети", Type: "select", Default: "tcp,udp", Options: opts("tcp,udp", "TCP и UDP", "tcp", "только TCP", "udp", "только UDP"), Adv: true},
		}},
	{ID: Hysteria2, Tag: "Hysteria2", Title: "Hysteria 2", Core: CoreXray, Net: "udp", DefaultPort: 443, TLS: true,
		Desc: "Быстрый протокол на QUIC (UDP). Хорош на плохих каналах. Нужен TLS-сертификат.",
		Fields: append(append([]Field{},
			Field{Key: "masquerade", Label: "Маскировка (ответ на чужой HTTP/3)", Type: "textarea", Help: "HTML-страница или URL вида https://example.com – сервер ответит ею постороннему", Adv: true},
			Field{Key: "obfs_password", Label: "Obfuscation salamander (пароль)", Type: "text", Help: "Пусто – без обфускации. Клиент должен знать тот же пароль", Adv: true},
			Field{Key: "up_mbps", Label: "Лимит отдачи, Мбит/с", Type: "number", Help: "0 – без ограничения", Adv: true},
			Field{Key: "down_mbps", Label: "Лимит загрузки, Мбит/с", Type: "number", Help: "0 – без ограничения", Adv: true},
			Field{Key: "udp_idle_timeout", Label: "Таймаут неактивного UDP, сек", Type: "number", Default: "60", Adv: true}), tlsFields...)},
	{ID: TUIC, Tag: "TUIC", Title: "TUIC v5", Core: CoreSingbox, Net: "udp", DefaultPort: 8444, TLS: true,
		Desc: "QUIC-протокол с мультиплексированием. Обслуживается ядром sing-box.",
		Fields: append(append([]Field{},
			Field{Key: "congestion", Label: "Контроль перегрузки", Type: "select", Default: "bbr", Options: opts("bbr", "bbr", "cubic", "cubic", "new_reno", "new_reno"), Adv: true},
			Field{Key: "udp_relay_mode", Label: "Режим UDP relay", Type: "select", Default: "native", Options: opts("native", "native", "quic", "quic"), Adv: true},
			Field{Key: "zero_rtt", Label: "0-RTT handshake", Type: "bool", Default: "false", Help: "Не рекомендуется: уязвим к replay-атакам", Adv: true},
			Field{Key: "heartbeat", Label: "Heartbeat", Type: "text", Default: "10s", Adv: true},
			Field{Key: "auth_timeout", Label: "Таймаут авторизации", Type: "text", Default: "3s", Adv: true}), tlsFields...)},
	{ID: Naive, Tag: "Naive", Title: "NaiveProxy", Core: CoreSingbox, Net: "both", DefaultPort: 8445, TLS: true,
		Desc: "HTTPS-прокси, неотличимый от обычного сайта в Chrome. Нужен домен и доверенный сертификат (Let's Encrypt): с самоподписанным обычные клиенты не подключатся.",
		Fields: append(append([]Field{},
			Field{Key: "quic_congestion", Label: "Контроль перегрузки QUIC", Type: "select", Default: "bbr", Options: opts("bbr", "bbr", "cubic", "cubic", "reno", "reno"), Adv: true},
			Field{Key: "naive_network", Label: "Сети", Type: "select", Default: "", Options: opts("", "TCP и UDP", "tcp", "только TCP", "udp", "только UDP"), Adv: true}), tlsFields...)},
	{ID: Masque, Tag: "MASQUE", Title: "MASQUE (CONNECT-IP)", Core: CoreMasque, Net: "both", DefaultPort: 8448, TLS: true,
		Desc: "IP-туннель поверх HTTP/3 (UDP) и HTTP/2 (TCP), RFC 9484. Экспериментальный: ядро sing-box 1.15 ставится отдельно и обновляется до последней версии. В подписку не попадает: настраивается в приложении вручную, готовый конфиг клиента даёт кнопка «Конфиг клиента». Трафик считается по подключению, а не по людям. Нужен домен и доверенный сертификат (Let's Encrypt), иначе клиенту придётся закреплять сертификат.",
		Fields: append(append([]Field{},
			Field{Key: "subnet", Label: "Подсеть туннелей клиентов", Type: "text", Default: "10.77.0.0/24", Help: "Каждому подключению выдаётся адрес из этой сети; сервер занимает первый", Adv: true},
			Field{Key: "mtu", Label: "MTU туннеля", Type: "number", Default: "1280", Help: "От 1280 до 65535", Adv: true}), tlsFields...)},
	{ID: Mieru, Tag: "Mieru", Title: "Mieru", Core: CoreMita, Net: "both", DefaultPort: 8446,
		Desc: "Протокол с собственным шифрованием поверх TCP или UDP. Обслуживается демоном mita.",
		Fields: []Field{
			{Key: "transport", Label: "Транспорт", Type: "select", Default: "TCP", Options: opts("TCP", "TCP", "UDP", "UDP")},
			{Key: "mtu", Label: "MTU (для UDP)", Type: "number", Default: "1400", Adv: true},
			{Key: "port_range", Label: "Диапазон портов (например 8446-8456)", Type: "text", Help: "Пусто – один порт подключения", Adv: true},
			{Key: "multiplexing", Label: "Мультиплексирование в клиенте", Type: "select", Default: "MULTIPLEXING_LOW", Options: opts(
				"MULTIPLEXING_OFF", "выкл", "MULTIPLEXING_LOW", "низкое", "MULTIPLEXING_MIDDLE", "среднее", "MULTIPLEXING_HIGH", "высокое"), Adv: true},
		}},
	{ID: MTProto, Tag: "MTProto", Title: "MTProto (Telegram)", Core: CoreMTG, Net: "tcp", DefaultPort: 8447,
		Desc: "Прокси для Telegram с маскировкой под TLS. Обслуживается mtg.",
		Fields: []Field{
			{Key: "engine", Label: "Движок", Type: "select", Default: "mtg", Options: opts("mtg", "mtg – один общий секрет", "telemt", "telemt – личный секрет у каждого пользователя, лимиты и сроки (только Linux)"), Adv: true,
				Help: "telemt сам применяет лимит трафика, срок и число устройств пользователя; трафик MTProto в панели при этом не считается"},
			{Key: "fake_tls", Label: "Домен маскировки (FakeTLS)", Type: "text", Default: "www.cloudflare.com"},
			{Key: "mtg_concurrency", Label: "Лимит соединений", Type: "number", Default: "8192", Adv: true},
			{Key: "prefer_ip", Label: "Предпочитать IP", Type: "select", Default: "prefer-ipv4", Options: opts("prefer-ipv4", "IPv4", "prefer-ipv6", "IPv6", "only-ipv4", "только IPv4", "only-ipv6", "только IPv6"), Adv: true},
		}},
	{ID: AWG, Tag: "AmneziaWG", Title: "AmneziaWG (классический)", Core: CoreAWG, Net: "udp", DefaultPort: 51821,
		Desc:   "WireGuard с обфускацией заголовков. Понимают Mihomo и роутеры Keenetic.",
		Fields: awgFields(false)},
	{ID: AWG3, Tag: "AmneziaWG-3.1", Title: "AmneziaWG 3.1", Core: CoreAWG, Net: "udp", DefaultPort: 51822,
		Desc:   "Полный набор обфускации AmneziaWG 3.1. Понимают приложения AmneziaVPN и AmneziaWG. Нужны AmneziaVPN 5.0.1.5 и новее, Keenetic 5.2 Alpha 11 и новее, Mihomo v1.19.30 и новее (version: 3).",
		Fields: awgFields(true)},
}

func awgFields(full bool) []Field {
	// у 3.1 своя подсеть по умолчанию, чтобы не пересекаться с классическим AmneziaWG на том же сервере
	subnet := "10.8.1.0/24"
	if full {
		subnet = "10.8.2.0/24"
	}
	f := []Field{
		{Key: "subnet", Label: "Подсеть туннеля", Type: "text", Default: subnet},
		{Key: "dns", Label: "DNS для клиентов", Type: "text", Default: "1.1.1.1", Adv: true},
		{Key: "mtu", Label: "MTU", Type: "number", Default: "1280", Adv: true},
		{Key: "keepalive", Label: "PersistentKeepalive (секунды или диапазон 25-35)", Type: "text", Default: "25", Adv: true},
		{Key: "jc", Label: "Jc (число мусорных пакетов)", Type: "number", Default: "4", Adv: true},
		{Key: "jmin", Label: "Jmin", Type: "number", Default: "40", Adv: true},
		{Key: "jmax", Label: "Jmax", Type: "number", Default: "70", Adv: true},
		{Key: "s1", Label: "S1 (мусор в init-пакете)", Type: "number", Default: "15", Adv: true},
		{Key: "s2", Label: "S2 (мусор в response-пакете)", Type: "number", Default: "68", Adv: true},
		{Key: "h1", Label: "H1", Type: "text", Default: "1", Adv: true},
		{Key: "h2", Label: "H2", Type: "text", Default: "2", Adv: true},
		{Key: "h3", Label: "H3", Type: "text", Default: "3", Adv: true},
		{Key: "h4", Label: "H4", Type: "text", Default: "4", Adv: true},
	}
	if full {
		f = append(f,
			Field{Key: "s3", Label: "S3 (cookie-пакет)", Type: "number", Default: "20", Adv: true},
			Field{Key: "s4", Label: "S4 (транспортные пакеты)", Type: "number", Default: "20", Adv: true, Help: "С защитой заголовков S1–S4 должны быть не меньше 12"},
			Field{Key: "i1", Label: "I1 (имитация протокола)", Type: "text", Adv: true, Help: "Цепочка сигнатур, например <b 0xc0000000><r 16>"},
			Field{Key: "i2", Label: "I2", Type: "text", Adv: true},
			Field{Key: "i3", Label: "I3", Type: "text", Adv: true},
			Field{Key: "i4", Label: "I4", Type: "text", Adv: true},
			Field{Key: "i5", Label: "I5", Type: "text", Adv: true},
			Field{Key: "rekey_after_time", Label: "RekeyAfterTime (с, число или диапазон)", Type: "text", Default: "100-120", Adv: true},
			Field{Key: "rekey_timeout", Label: "RekeyTimeout", Type: "text", Default: "3-8", Adv: true},
			Field{Key: "reject_after_time", Label: "RejectAfterTime", Type: "text", Default: "150-180", Adv: true},
			Field{Key: "keepalive_timeout", Label: "KeepaliveTimeout", Type: "text", Default: "7-13", Adv: true},
			Field{Key: "max_handshake_attempts", Label: "MaxHandshakeAttempts", Type: "text", Default: "15-20", Adv: true},
			Field{Key: "content_padding_addition", Label: "ContentPaddingAddition", Type: "text", Default: "10-100", Adv: true},
			Field{Key: "header_key", Label: "Ключ защиты заголовков (hex или base64, 32 байта)", Type: "text", Adv: true, Help: "Создаётся автоматически; клиент и сервер должны знать один и тот же"},
		)
	}
	return f
}

var byID = func() map[Kind]*Info {
	m := map[Kind]*Info{}
	for i := range Catalog {
		c := &Catalog[i]
		// Общие расширенные поля: слушающий адрес и sniffing – только у подключений Xray;
		// адрес и порт для ссылок – у всех.
		for _, f := range commonAdv {
			if c.Core != CoreXray && f.Key != "external_host" && f.Key != "external_port" {
				continue
			}
			c.Fields = append(c.Fields, f)
		}
		m[c.ID] = c
	}
	return m
}()

// Get возвращает описание типа подключения.
func Get(k Kind) (*Info, bool) {
	i, ok := byID[k]
	return i, ok
}
