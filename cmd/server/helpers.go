package main

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"net"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/proto"
)

// linkHost – адрес сервера для ссылок: из настроек, иначе по адресу, на который обратились к панели.
func linkHost(c *gin.Context) string {
	if h := db.GetSetting("public_host", ""); h != "" {
		return h
	}
	host := c.Request.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
}

func isLoopback(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// rememberHost сохраняет адрес сервера при первом обращении не с localhost:
// по нему выпускается самоподписанный сертификат, поэтому адрес должен быть настоящим.
func rememberHost(c *gin.Context) {
	if db.GetSetting("public_host", "") != "" {
		return
	}
	if h := linkHost(c); h != "" && !isLoopback(h) && validHostName(h) {
		_ = db.SetSetting("public_host", h)
	}
}

// applyCores приводит ядра в соответствие с БД: членство пользователей, конфиги, перезапуск.
func applyCores() error {
	if err := db.SyncMembership(); err != nil {
		return err
	}
	return core.ApplyAll()
}

// reservedLocalPort – внутренние порты панели на 127.0.0.1: внутренний адрес панели, ответы постороннему (Hysteria) и сайт-заглушка.
func reservedLocalPort(port int) bool {
	return port == 10380 || port == 10398 || port == 10399
}

// portTaken: порт уже занят подключением из БД (с учётом сети) или служебным портом панели.
func portTaken(port int, netw string, exceptID int) bool {
	if port == 8080 || port == 10085 || reservedLocalPort(port) || port == panelPort() {
		return true
	}
	if t := core.LoadPanelTLS(); t.Mode != "off" && t.Mode != "" && t.Port == port && netw != "udp" {
		return true // порт HTTPS самой панели
	}
	inbounds, _ := db.GetInbounds()
	for _, ib := range inbounds {
		if ib.ID == exceptID || ib.Port != port {
			continue
		}
		other := "tcp"
		if info, ok := proto.Get(proto.Kind(ib.Kind)); ok {
			other = info.Net
		}
		if other == "both" || netw == "both" || other == netw {
			return true
		}
	}
	return false
}

// pickPort подбирает свободный порт: сначала привычный для типа, затем случайный высокий.
func pickPort(info *proto.Info) int {
	if !portTaken(info.DefaultPort, info.Net, 0) {
		return info.DefaultPort
	}
	return pickRandomPort(func(p int) bool { return !portTaken(p, info.Net, 0) && !portListening(p) })
}

// pickRandomPort берёт случайный свободный порт из 10240–59999. Прежний перебор с шагом 137 от 20000 ставил порты
// всех серверов в одну и ту же арифметическую прогрессию: по ней сервер Kitsune легко узнать.
func pickRandomPort(free func(int) bool) int {
	const lo, span = 10240, 49760
	for i := 0; i < 200; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(span))
		if err != nil {
			break
		}
		if p := lo + int(n.Int64()); free(p) {
			return p
		}
	}
	for p := lo; p < lo+span; p++ { // запасной перебор, если случайные попытки не нашли свободный
		if free(p) {
			return p
		}
	}
	return 0
}

func uniqueTag(base string) string {
	tag := db.CleanName(base)
	if tag == "" {
		tag = "inbound"
	}
	existing := map[string]bool{}
	inbounds, _ := db.GetInbounds()
	for _, ib := range inbounds {
		existing[ib.Tag] = true
	}
	cand := tag
	for i := 2; existing[cand]; i++ {
		cand = tag + "-" + strconv.Itoa(i)
	}
	return cand
}

func jsonUnmarshal(raw string, v any) error { return json.Unmarshal([]byte(raw), v) }

// migrateLegacyInbounds переводит шлюзы старого формата (без типа) в каталог протоколов.
func migrateLegacyInbounds() {
	inbounds, err := db.GetInbounds()
	if err != nil {
		return
	}
	for _, ib := range inbounds {
		if ib.Kind != "" {
			continue
		}
		var kind proto.Kind
		switch ib.Protocol {
		case "vless":
			kind = proto.VlessReality
		case "trojan":
			kind = proto.TrojanGRPC
		case "vmess":
			kind = proto.VmessWS
		case "shadowsocks":
			kind = proto.SS2022
		case "hysteria", "hysteria2":
			kind = proto.Hysteria2
		case "tuic":
			kind = proto.TUIC
		case "naive", "naiveproxy":
			kind = proto.Naive
		case "mieru":
			kind = proto.Mieru
		default:
			continue
		}
		s := proto.Settings{SNI: ib.SNI, PrivateKey: ib.PrivateKey, PublicKey: ib.PublicKey, ShortIDs: ib.ShortID}
		if err := s.Fill(kind); err != nil {
			continue
		}
		_, _ = db.DB.Exec("UPDATE inbounds SET kind = ?, protocol = ?, settings = ?, sni = ?, private_key = ?, public_key = ?, short_id = ? WHERE id = ?",
			string(kind), protocolName(kind), s.JSON(), s.SNI, s.PrivateKey, s.PublicKey, s.ShortIDs, ib.ID)
	}
}

func strconvI(n int) string { return strconv.Itoa(n) }
