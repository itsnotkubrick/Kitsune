package proto

import "strconv"

// MASQUE не имеет ссылки-подписки ни в одном клиенте, поэтому пользователь получает готовый конфиг и вставляет его в приложение сам.
// Здесь два варианта: sing-box 1.15 и новее (masque-client) и Xray 26.10.10 и новее (его понимает v2rayN). Они проверены друг с другом
// во всех сочетаниях сервера и клиента по HTTP/3 и HTTP/2.

// MasqueVersions – версии HTTP, которые можно выбрать в клиенте: 3 (QUIC, UDP) и 2 (TCP). sing-box умеет ещё 1 (HTTP/1.1), Xray нет.
func MasqueVersions(xray bool) []int {
	if xray {
		return []int{3, 2}
	}
	return []int{3, 2, 1}
}

func masqueVersionOK(v int, xray bool) int {
	for _, x := range MasqueVersions(xray) {
		if x == v {
			return v
		}
	}
	return 3
}

// MasqueSingboxConfig – готовый конфиг клиента sing-box 1.15+: локальный прокси на 127.0.0.1:1080 и туннель MASQUE.
func (p *Profile) MasqueSingboxConfig(version int) M {
	version = masqueVersionOK(version, false)
	tls := M{"enabled": true}
	if p.SNI != "" {
		tls["server_name"] = p.SNI
	}
	if p.Insecure {
		tls["insecure"] = true // самоподписанный сертификат: с доменом и Let's Encrypt этого не нужно
	}
	ep := M{"type": "masque-client", "tag": "masque-out", "server": p.Host, "server_port": p.Port,
		"username": p.U.Name, "password": p.U.Password, "version": version, "tls": tls,
		"mtu": atoiOr(p.S.MTU, 1280)}
	return M{
		"log":       M{"level": "info", "timestamp": true},
		"inbounds":  []M{{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 1080}},
		"endpoints": []M{ep},
		"outbounds": []M{{"type": "direct", "tag": "direct"}},
		"route":     M{"final": "masque-out"},
	}
}

// MasqueXrayConfig – готовый конфиг клиента Xray 26.10.10+ (для v2rayN: «Добавить свой конфиг»): локальный SOCKS на 127.0.0.1:10808.
func (p *Profile) MasqueXrayConfig(version int) M {
	version = masqueVersionOK(version, true)
	alpn := "h3"
	if version == 2 {
		alpn = "h2"
	}
	tls := M{"serverName": p.SNI, "alpn": []string{alpn}}
	if p.Insecure && p.Pin != "" {
		tls["pinnedPeerCertSha256"] = p.Pin // allowInsecure из Xray убран: самоподписанный сертификат закрепляется хешем
	}
	host := p.SNI
	if host == "" {
		host = p.Host
	}
	return M{
		"log":      M{"loglevel": "warning"},
		"inbounds": []M{{"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": M{"udp": true}}},
		"outbounds": []M{{
			"tag": "masque-out", "protocol": "masque",
			"settings": M{"address": p.Host, "port": p.Port},
			"streamSettings": M{
				"method":         "masque",
				"masqueSettings": M{"host": host, "user": p.U.Name, "pass": p.U.Password},
				"security":       "tls",
				"tlsSettings":    tls,
			},
		}},
	}
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return def
}
