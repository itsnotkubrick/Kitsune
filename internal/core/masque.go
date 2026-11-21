package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"kitsune/internal/db"
	"kitsune/internal/proto"
)

// MasqueProc – отдельный экземпляр sing-box для MASQUE. MASQUE есть только в sing-box 1.15 и новее (пока предрелизы), а основной sing-box
// держится на проверенной версии для TUIC и NaiveProxy. Поэтому MASQUE-ядро ставится отдельно и обновляется до последней версии.
var MasqueProc = NewProc("masque")

const masqueConfig = "masque.json"

// MasqueBinary – бинарник sing-box для MASQUE (bin/sing-box-masque).
func MasqueBinary() string { return FindBinary("sing-box-masque") }

// masqueServerAddr из подсети туннелей делает адрес сервера: первый адрес сети с её длиной префикса (10.77.0.0/24 -> 10.77.0.1/24).
func masqueServerAddr(subnet string) (string, error) {
	ip, n, err := net.ParseCIDR(subnet)
	if err != nil || ip.To4() == nil {
		return "", fmt.Errorf("подсеть туннелей «%s» должна быть IPv4 вида 10.77.0.0/24", subnet)
	}
	ones, bits := n.Mask.Size()
	if bits != 32 || ones < 16 || ones > 30 {
		return "", fmt.Errorf("длина префикса подсети «%s» должна быть от 16 до 30", subnet)
	}
	base := n.IP.To4()
	first := net.IPv4(base[0], base[1], base[2], base[3]+1)
	return fmt.Sprintf("%s/%d", first.String(), ones), nil
}

func masqueMTU(s string) (int, error) {
	if s == "" {
		return 1280, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 1280 || v > 65535 {
		return 0, fmt.Errorf("MTU туннеля должен быть числом от 1280 до 65535")
	}
	return v, nil
}

// BuildMasqueConfig собирает конфиг sing-box для MASQUE. Второе значение – есть ли что запускать.
// Учёт трафика: sing-box не передаёт имя пользователя в маршрутизацию MASQUE, поэтому по людям трафик
// не считается и лимиты на MASQUE не действуют; пользователи различаются только при входе (логин и пароль).
func BuildMasqueConfig(env proto.Env) (proto.M, bool, error) {
	inbounds, err := db.GetInbounds()
	if err != nil {
		return nil, false, err
	}
	users, err := db.GetUsers()
	if err != nil {
		return nil, false, err
	}
	return buildMasque(inbounds, users, db.GroupMap(), env, LoadXraySettings().BlockPrivate, LoadCoreSettings().Singbox)
}

// buildMasque – сборка без обращения к базе (для тестов): подключения, пользователи, карта групп, адрес сервера.
func buildMasque(inbounds []db.Inbound, users []db.User, gm map[int]map[int]bool, env proto.Env, blockPrivate bool, cs SingboxSettings) (proto.M, bool, error) {
	var eps []proto.M
	for _, ib := range inbounds {
		if !ib.Enable || ib.Kind != string(proto.Masque) {
			continue
		}
		s := proto.ParseSettings(ib.Settings)
		crt, key, _, err := s.TLSFiles(env)
		if err != nil {
			return nil, false, fmt.Errorf("подключение %s: %w", ib.Tag, err)
		}
		addr, err := masqueServerAddr(firstNonEmpty(s.Subnet, "10.77.0.0/24"))
		if err != nil {
			return nil, false, fmt.Errorf("подключение %s: %w", ib.Tag, err)
		}
		mtu, err := masqueMTU(s.MTU)
		if err != nil {
			return nil, false, fmt.Errorf("подключение %s: %w", ib.Tag, err)
		}
		var us []proto.M
		for _, u := range users {
			if u.Active() && db.Allowed(gm, u, ib.ID) {
				us = append(us, proto.M{"username": u.Name, "password": u.Password})
			}
		}
		if len(us) == 0 {
			continue // без пользователей сервер не стартует: запустится, когда появится первый
		}
		tls := proto.M{"enabled": true, "certificate_path": crt, "key_path": key}
		if s.SNI != "" {
			tls["server_name"] = s.SNI
		}
		eps = append(eps, proto.M{"type": "masque-server", "tag": ib.Tag, "listen": firstNonEmpty(s.Listen, "::"), "listen_port": ib.Port,
			"version": []int{1, 2, 3}, "users": us, "tls": tls, "address": []string{addr}, "mtu": mtu})
	}
	if len(eps) == 0 {
		return nil, false, nil
	}
	rules := []proto.M{}
	if blockPrivate {
		rules = append(rules, proto.M{"ip_is_private": true, "action": "reject"})
	}
	cfg := proto.M{
		"log":       proto.M{"level": cs.LogLevel, "timestamp": cs.LogTimestamp},
		"endpoints": eps,
		"outbounds": []proto.M{{"type": "direct", "tag": "direct"}},
		"route":     proto.M{"rules": rules, "final": "direct", "default_domain_resolver": "local"},
		"dns":       proto.M{"servers": []proto.M{{"tag": "local", "type": "local"}}},
	}
	return cfg, true, nil
}

// ApplyMasque пересобирает конфиг и перезапускает sing-box для MASQUE; если подключений MASQUE нет – останавливает.
func ApplyMasque() error {
	cfg, any, err := BuildMasqueConfig(PublicEnv())
	if err != nil {
		return err
	}
	if !any {
		MasqueProc.Stop()
		_ = os.Remove(masqueConfig)
		return nil
	}
	bin := MasqueBinary()
	if bin == "" {
		return errors.New("ядро MASQUE (sing-box 1.15 и новее) не установлено")
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	tmp := "masque.new.json"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := testSingbox(bin, tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("ядро MASQUE не приняло конфиг: %w", err)
	}
	if err := os.Rename(tmp, masqueConfig); err != nil {
		return err
	}
	abs, _ := filepath.Abs(masqueConfig)
	return MasqueProc.Start(bin, []string{"run", "-c", abs}, nil, "")
}
