package proto

import (
	"net"
	"strings"
)

// isDomain – значение похоже на доменное имя: не пусто, не IP-адрес, есть точка.
func isDomain(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && net.ParseIP(strings.Trim(v, "[]")) == nil && strings.Contains(v, ".")
}

// NeedsDomain – подключению нужен домен, а его нет. Единое правило для панели:
// NaiveProxy всегда работает по домену (в SNI или в адресе для ссылок клиентов); при автоматическом
// сертификате (acme) домен нужен именно в SNI: сертификат выпускается на него, а адрес ссылок его не заменяет.
// Остальные TLS-протоколы – когда сертификат выпускается автоматически (acme), а в SNI не домен.
func NeedsDomain(kind Kind, s Settings) bool {
	info, ok := Get(kind)
	if !ok || !info.TLS {
		return false
	}
	switch {
	case kind == Naive && s.CertMode == "acme":
		return !isDomain(s.SNI)
	case kind == Naive:
		return !isDomain(s.SNI) && !isDomain(s.ExternalHost)
	case s.CertMode == "acme":
		return !isDomain(s.SNI)
	}
	return false
}
