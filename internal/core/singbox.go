package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"kitsune/internal/acct"
	"kitsune/internal/db"
	"kitsune/internal/proto"
)

// SingboxProc – sing-box под присмотром панели: обслуживает TUIC и NaiveProxy.
var SingboxProc = NewProc("singbox")

const (
	singboxConfig  = "singbox.json"
	singboxAPIAddr = "127.0.0.1:19090"
)

func SingboxBinary() string { return FindBinary("sing-box") }

// BuildSingboxConfig собирает конфиг sing-box. Второе значение – есть ли что запускать.
func BuildSingboxConfig(env proto.Env) (proto.M, bool, error) {
	inbounds, err := db.GetInbounds()
	if err != nil {
		return nil, false, err
	}
	users, err := db.GetUsers()
	if err != nil {
		return nil, false, err
	}
	xs := LoadXraySettings()
	cs := LoadCoreSettings().Singbox
	gm := db.GroupMap()

	px, err := accounting()
	if err != nil {
		return nil, false, fmt.Errorf("не удалось запустить учёт трафика: %w", err)
	}
	px.BlockPrivate(xs.BlockPrivate)

	var in []proto.M
	var outs []proto.M
	var rules []proto.M
	outSeen := map[string]bool{}
	for _, ib := range inbounds {
		info, ok := proto.Get(proto.Kind(ib.Kind))
		if !ib.Enable || !ok || info.Core != proto.CoreSingbox {
			continue
		}
		s := proto.ParseSettings(ib.Settings)
		crt, key, _, err := s.TLSFiles(env)
		if err != nil {
			return nil, false, fmt.Errorf("подключение %s: %w", ib.Tag, err)
		}
		tls := proto.M{"enabled": true, "certificate_path": crt, "key_path": key}
		if s.SNI != "" {
			tls["server_name"] = s.SNI
		}
		listen := firstNonEmpty(s.Listen, "::")
		inbound := proto.M{"tag": ib.Tag, "listen": listen, "listen_port": ib.Port, "tls": tls}

		var us []proto.M
		for _, u := range users {
			if !u.Active() || !db.Allowed(gm, u, ib.ID) {
				continue
			}
			switch proto.Kind(ib.Kind) {
			case proto.TUIC:
				us = append(us, proto.M{"name": u.Name, "uuid": u.UUID, "password": u.Password})
			case proto.Naive:
				us = append(us, proto.M{"username": u.Name, "password": u.Password})
			}
			// Каждый пользователь в каждом подключении идёт в интернет через прокси учёта под своим именем.
			email := db.ClientEmail(u.Name, ib.Tag)
			tag := "u:" + email
			if !outSeen[tag] {
				outSeen[tag] = true
				outs = append(outs, proto.M{"type": "socks", "tag": tag, "server": "127.0.0.1", "server_port": px.Port(), "version": "5",
					"username": email, "password": px.Token()})
				rules = append(rules, proto.M{"inbound": []string{ib.Tag}, "auth_user": []string{u.Name}, "outbound": tag})
			}
		}
		if len(us) == 0 && proto.Kind(ib.Kind) == proto.Naive {
			continue // NaiveProxy не стартует без пользователей: запустится, когда появится первый
		}
		if us == nil {
			us = []proto.M{}
		}
		switch proto.Kind(ib.Kind) {
		case proto.TUIC:
			tls["alpn"] = []string{"h3"}
			inbound["type"] = "tuic"
			inbound["users"] = us
			inbound["congestion_control"] = firstNonEmpty(s.Congestion, "bbr")
			inbound["auth_timeout"] = firstNonEmpty(s.AuthTimeout, "3s")
			inbound["zero_rtt_handshake"] = s.ZeroRTT == "true"
			inbound["heartbeat"] = firstNonEmpty(s.Heartbeat, "10s")
		case proto.Naive:
			inbound["type"] = "naive"
			inbound["users"] = us
			if s.NaiveNetwork != "" {
				inbound["network"] = s.NaiveNetwork
			}
			if s.QUICCongestion != "" {
				inbound["quic_congestion_control"] = s.QUICCongestion
			}
			if cs.TCPFastOpen {
				inbound["tcp_fast_open"] = true
			}
		}
		in = append(in, inbound)
	}
	if len(in) == 0 {
		return nil, false, nil
	}

	routeRules := []proto.M{}
	if xs.BlockPrivate {
		routeRules = append(routeRules, proto.M{"ip_is_private": true, "action": "reject"})
	}
	routeRules = append(routeRules, rules...)
	outs = append(outs, proto.M{"type": "direct", "tag": "direct"})

	cfg := proto.M{
		"log":       proto.M{"level": cs.LogLevel, "timestamp": cs.LogTimestamp},
		"inbounds":  in,
		"outbounds": outs,
		"route":     proto.M{"rules": routeRules, "final": "direct", "default_domain_resolver": "local"},
		"dns":       proto.M{"servers": []proto.M{{"tag": "local", "type": "local"}}},
	}
	return cfg, true, nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func testSingbox(bin, path string) error {
	cmd := exec.Command(bin, "check", "-c", path)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		return errors.New(lastLines(lines, 3))
	}
	return nil
}

// ApplySingbox пересобирает конфиг и перезапускает sing-box; если шлюзов sing-box нет – останавливает.
func ApplySingbox() error {
	cfg, any, err := BuildSingboxConfig(PublicEnv())
	if err != nil {
		return err
	}
	if !any {
		SingboxProc.Stop()
		_ = os.Remove(singboxConfig)
		return nil
	}
	bin := SingboxBinary()
	if bin == "" {
		return errors.New("ядро sing-box не установлено (нужно для TUIC и NaiveProxy)")
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	tmp := "singbox.new.json"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := testSingbox(bin, tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("sing-box не принял конфиг: %w", err)
	}
	if err := os.Rename(tmp, singboxConfig); err != nil {
		return err
	}
	abs, _ := filepath.Abs(singboxConfig)
	return SingboxProc.Start(bin, []string{"run", "-c", abs}, nil, "")
}

// ---- Учёт трафика sing-box: через локальный SOCKS5-прокси панели (internal/acct) ----

var (
	acctMu    sync.Mutex
	acctProxy *acct.Proxy
)

// accounting возвращает прокси учёта, создавая его при первом обращении.
func accounting() (*acct.Proxy, error) {
	acctMu.Lock()
	defer acctMu.Unlock()
	if acctProxy == nil {
		p, err := acct.New()
		if err != nil {
			return nil, err
		}
		acctProxy = p
	}
	return acctProxy, nil
}

// DrainAcct отдаёт прирост трафика пользователей sing-box: email подключения -> байты.
func DrainAcct() map[string]int64 {
	acctMu.Lock()
	p := acctProxy
	acctMu.Unlock()
	if p == nil {
		return nil
	}
	return p.Drain()
}
