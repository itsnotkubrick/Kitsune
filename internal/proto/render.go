package proto

import (
	"strconv"
	"strings"
)

// Clash возвращает прокси для Mihomo/Clash Meta. nil – тип не поддерживается этим клиентом.
func (p *Profile) Clash() M {
	s, u := p.S, p.U
	base := M{"name": p.Name, "server": p.Host, "port": p.Port}
	set := func(kv M) M {
		for k, v := range kv {
			base[k] = v
		}
		return base
	}
	switch p.Kind {
	case VlessReality:
		m := M{"type": "vless", "uuid": u.UUID, "network": "tcp", "udp": true, "tls": true, "servername": p.SNI,
			"client-fingerprint": firstNonEmpty(s.Fingerprint, "chrome"),
			"reality-opts":       M{"public-key": s.PublicKey, "short-id": firstSID(s)}}
		if f := s.flowFor(u); f != "" {
			m["flow"] = f
		}
		return set(m)
	case VlessXHTTP:
		x := M{"path": s.Path, "mode": firstNonEmpty(s.Mode, "auto")}
		if s.Host != "" {
			x["host"] = s.Host
		}
		return set(M{"type": "vless", "uuid": u.UUID, "network": "xhttp", "udp": true, "tls": true, "servername": p.SNI,
			"client-fingerprint": firstNonEmpty(s.Fingerprint, "chrome"), "xhttp-opts": x,
			"reality-opts": M{"public-key": s.PublicKey, "short-id": firstSID(s)}})
	case VlessWS:
		return set(M{"type": "vless", "uuid": u.UUID, "network": "ws", "udp": true, "tls": true, "servername": p.SNI,
			"skip-cert-verify": p.Insecure, "client-fingerprint": firstNonEmpty(s.Fingerprint, "chrome"), "alpn": []string{"http/1.1"},
			"ws-opts": M{"path": s.Path, "headers": wsHeaders(firstNonEmpty(s.Host, p.SNI))}})
	case VmessWS:
		return set(M{"type": "vmess", "uuid": u.UUID, "alterId": 0, "cipher": "auto", "network": "ws", "udp": true, "tls": true,
			"servername": p.SNI, "skip-cert-verify": p.Insecure, "client-fingerprint": firstNonEmpty(s.Fingerprint, "chrome"),
			"ws-opts": M{"path": s.Path, "headers": wsHeaders(firstNonEmpty(s.Host, p.SNI))}})
	case TrojanGRPC:
		return set(M{"type": "trojan", "password": u.Password, "network": "grpc", "udp": true, "sni": p.SNI,
			"skip-cert-verify": p.Insecure, "client-fingerprint": firstNonEmpty(s.Fingerprint, "chrome"), "alpn": []string{"h2"},
			"grpc-opts": M{"grpc-service-name": s.ServiceName}})
	case SS2022:
		return set(M{"type": "ss", "cipher": s.Method, "password": s.ServerKey + ":" + p.userSSKey(), "udp": true})
	case Hysteria2:
		m := M{"type": "hysteria2", "password": u.Password, "sni": p.SNI, "skip-cert-verify": p.Insecure, "alpn": []string{"h3"}}
		if s.ObfsPassword != "" {
			m["obfs"] = "salamander"
			m["obfs-password"] = s.ObfsPassword
		}
		return set(m)
	case TUIC:
		return set(M{"type": "tuic", "uuid": u.UUID, "password": u.Password, "alpn": []string{"h3"}, "sni": p.SNI,
			"congestion-controller": firstNonEmpty(s.Congestion, "bbr"), "udp-relay-mode": firstNonEmpty(s.UDPRelayMode, "native"),
			"skip-cert-verify": p.Insecure, "reduce-rtt": false})
	case AWG:
		if p.AWG == nil {
			return nil
		}
		opt := M{}
		for _, k := range []string{"jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"} {
			if v := strings.TrimSpace(s.AWGParams()[strings.ToUpper(k[:1])+k[1:]]); v != "" {
				if n, err := strconv.Atoi(v); err == nil {
					opt[k] = n
				}
			}
		}
		return set(M{"type": "wireguard", "ip": p.AWG.IP, "private-key": p.AWG.PrivateKey, "public-key": s.PublicKey,
			"pre-shared-key": p.AWG.PSK, "allowed-ips": []string{"0.0.0.0/0"}, "udp": true,
			"mtu": intOf(s.MTU, 1280), "remote-dns-resolve": true, "dns": []string{firstNonEmpty(s.DNS, "1.1.1.1")},
			"amnezia-wg-option": opt})
	case AWG3:
		if p.AWG == nil {
			return nil
		}
		// version: 3 включает в Mihomo ядро с защитой заголовков; без него ключ игнорируется
		opt := M{"version": 3}
		params := s.AWGParams()
		for _, k := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4"} {
			if n, err := strconv.Atoi(strings.TrimSpace(params[strings.ToUpper(k[:1])+k[1:]])); err == nil {
				opt[k] = n
			}
		}
		for _, k := range []string{"h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"} {
			if v := strings.TrimSpace(params[strings.ToUpper(k)]); v != "" {
				opt[k] = v
			}
		}
		if s.HeaderKey != "" {
			opt["header-protection-key"] = ClientHeaderKey(s.HeaderKey)
		}
		return set(M{"type": "wireguard", "ip": p.AWG.IP, "private-key": p.AWG.PrivateKey, "public-key": s.PublicKey,
			"pre-shared-key": p.AWG.PSK, "allowed-ips": []string{"0.0.0.0/0"}, "udp": true,
			"mtu": intOf(s.MTU, 1280), "remote-dns-resolve": true, "dns": []string{firstNonEmpty(s.DNS, "1.1.1.1")},
			"persistent-keepalive": firstInt(s.Keepalive, 25), "amnezia-wg-option": opt})
	case Mieru:
		return set(M{"type": "mieru", "transport": firstNonEmpty(s.Transport, "TCP"), "username": u.Name, "password": u.Password,
			"multiplexing": firstNonEmpty(s.Multiplexing, "MULTIPLEXING_LOW")})
	}
	return nil
}

// wsHeaders – заголовки WebSocket; пустое имя (домена нет) не пишем.
func wsHeaders(host string) M {
	if host == "" {
		return M{}
	}
	return M{"Host": host}
}

func singTLS(p *Profile, alpn ...string) M {
	t := M{"enabled": true}
	if p.SNI != "" {
		t["server_name"] = p.SNI
	}
	if p.Insecure {
		t["insecure"] = true
	}
	if len(alpn) > 0 {
		t["alpn"] = alpn
	}
	if p.S.Fingerprint != "" && (p.Kind == VlessWS || p.Kind == VmessWS || p.Kind == TrojanGRPC) {
		t["utls"] = M{"enabled": true, "fingerprint": p.S.Fingerprint}
	}
	return t
}

// SingBox возвращает исходящее подключение sing-box. nil – sing-box этот тип не поддерживает.
func (p *Profile) SingBox() M {
	s, u := p.S, p.U
	base := M{"tag": p.Name, "server": p.Host, "server_port": p.Port}
	set := func(kv M) M {
		for k, v := range kv {
			base[k] = v
		}
		return base
	}
	switch p.Kind {
	case VlessReality:
		m := M{"type": "vless", "uuid": u.UUID, "packet_encoding": "xudp",
			"tls": M{"enabled": true, "server_name": p.SNI, "utls": M{"enabled": true, "fingerprint": firstNonEmpty(s.Fingerprint, "chrome")},
				"reality": M{"enabled": true, "public_key": s.PublicKey, "short_id": firstSID(s)}}}
		if f := s.flowFor(u); f != "" {
			m["flow"] = f
		}
		return set(m)
	case VlessWS:
		return set(M{"type": "vless", "uuid": u.UUID, "packet_encoding": "xudp", "tls": singTLS(p, "http/1.1"),
			"transport": M{"type": "ws", "path": s.Path, "headers": wsHeaders(firstNonEmpty(s.Host, p.SNI))}})
	case VmessWS:
		return set(M{"type": "vmess", "uuid": u.UUID, "security": "auto", "tls": singTLS(p, "http/1.1"),
			"transport": M{"type": "ws", "path": s.Path, "headers": wsHeaders(firstNonEmpty(s.Host, p.SNI))}})
	case TrojanGRPC:
		return set(M{"type": "trojan", "password": u.Password, "tls": singTLS(p, "h2"),
			"transport": M{"type": "grpc", "service_name": s.ServiceName}})
	case SS2022:
		return set(M{"type": "shadowsocks", "method": s.Method, "password": s.ServerKey + ":" + p.userSSKey()})
	case Hysteria2:
		m := M{"type": "hysteria2", "password": u.Password, "tls": singTLS(p, "h3")}
		if s.ObfsPassword != "" {
			m["obfs"] = M{"type": "salamander", "password": s.ObfsPassword}
		}
		return set(m)
	case TUIC:
		return set(M{"type": "tuic", "uuid": u.UUID, "password": u.Password, "congestion_control": firstNonEmpty(s.Congestion, "bbr"),
			"udp_relay_mode": firstNonEmpty(s.UDPRelayMode, "native"), "tls": singTLS(p, "h3")})
	case Naive:
		// sing-box (и Karing) отвергают insecure в naive: с самоподписанным сертификатом узел в подписку не кладём.
		if p.Insecure {
			return nil
		}
		return set(M{"type": "naive", "username": u.Name, "password": u.Password, "tls": singTLS(p)})
	}
	return nil
}

func xrayTLS(p *Profile, alpn ...string) M {
	t := M{"serverName": p.SNI, "fingerprint": firstNonEmpty(p.S.Fingerprint, "chrome"), "alpn": alpn}
	if p.Insecure && p.Pin != "" {
		t["pinnedPeerCertSha256"] = p.Pin
	}
	return t
}

// XrayOutbound возвращает исходящее подключение Xray: им «Здоровье» проверяет подключения с самого сервера.
// nil – тип проверить клиентом Xray нельзя.
func (p *Profile) XrayOutbound() M {
	s, u := p.S, p.U
	reality := M{"serverName": p.SNI, "fingerprint": firstNonEmpty(s.Fingerprint, "chrome"), "password": s.PublicKey,
		"shortId": firstSID(s), "spiderX": firstNonEmpty(s.SpiderX, "/")}
	vnext := func(user M) M {
		return M{"vnext": []M{{"address": p.Host, "port": p.Port, "users": []M{user}}}}
	}
	switch p.Kind {
	case VlessReality:
		user := M{"id": u.UUID, "encryption": "none"}
		if f := s.flowFor(u); f != "" {
			user["flow"] = f
		}
		return M{"protocol": "vless", "settings": vnext(user),
			"streamSettings": M{"network": "tcp", "security": "reality", "realitySettings": reality}}
	case VlessXHTTP:
		x := M{"path": s.Path, "mode": firstNonEmpty(s.Mode, "auto")}
		if s.Host != "" {
			x["host"] = s.Host
		}
		return M{"protocol": "vless", "settings": vnext(M{"id": u.UUID, "encryption": "none"}),
			"streamSettings": M{"network": "xhttp", "security": "reality", "xhttpSettings": x, "realitySettings": reality}}
	case VlessWS:
		return M{"protocol": "vless", "settings": vnext(M{"id": u.UUID, "encryption": "none"}),
			"streamSettings": M{"network": "ws", "security": "tls", "tlsSettings": xrayTLS(p, "http/1.1"), "wsSettings": wsSettings(s)}}
	case VmessWS:
		return M{"protocol": "vmess", "settings": vnext(M{"id": u.UUID, "security": "auto"}),
			"streamSettings": M{"network": "ws", "security": "tls", "tlsSettings": xrayTLS(p, "http/1.1"), "wsSettings": wsSettings(s)}}
	case TrojanGRPC:
		return M{"protocol": "trojan", "settings": M{"servers": []M{{"address": p.Host, "port": p.Port, "password": u.Password}}},
			"streamSettings": M{"network": "grpc", "security": "tls", "tlsSettings": xrayTLS(p, "h2"), "grpcSettings": M{"serviceName": s.ServiceName}}}
	case SS2022:
		return M{"protocol": "shadowsocks", "settings": M{"servers": []M{{"address": p.Host, "port": p.Port, "method": s.Method,
			"password": s.ServerKey + ":" + p.userSSKey()}}}}
	case Hysteria2:
		st := M{"network": "hysteria", "security": "tls", "tlsSettings": xrayTLS(p, "h3"),
			"hysteriaSettings": M{"version": 2, "auth": u.Password}}
		if s.ObfsPassword != "" {
			st["finalmask"] = M{"udp": []M{{"type": "salamander", "settings": M{"password": s.ObfsPassword}}}}
		}
		return M{"protocol": "hysteria", "settings": M{"version": 2, "address": p.Host, "port": p.Port}, "streamSettings": st}
	}
	return nil
}

// Title – читаемое название типа для интерфейса.
func (k Kind) Title() string {
	if i, ok := Get(k); ok {
		return i.Title
	}
	return strings.ToUpper(string(k))
}

// SingboxProbeOutbound – исходящее sing-box для проверки с самого сервера. Самоподписанный сертификат клиенту
// указывается как доверенный файл (NaiveProxy не умеет insecure). nil – тип sing-box не проверяет.
func (p *Profile) SingboxProbeOutbound(env Env) M {
	if p.Kind != TUIC && p.Kind != Naive {
		return nil
	}
	o := p.SingBox()
	if o == nil {
		return nil
	}
	if p.Kind == Naive && p.Insecure {
		if crt, _, _, err := p.S.TLSFiles(env); err == nil {
			// проверка идёт на 127.0.0.1: имя для сверки с сертификатом берём то, на которое он выпущен (в сеть оно не уходит)
			o["tls"] = M{"enabled": true, "server_name": firstNonEmpty(p.SNI, p.S.SNI, env.Host), "certificate_path": crt}
		}
	}
	return o
}
