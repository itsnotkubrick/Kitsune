package core

import (
	"encoding/json"
	"runtime"

	"fmt"
	"strconv"
	"sync"

	"kitsune/internal/awg"
	"kitsune/internal/db"
	"kitsune/internal/proto"
)

var (
	awgMu      sync.Mutex
	awgServers = map[int]*awg.Server{}
)

func awgIface(id int) string { return "awg" + strconv.Itoa(id) }

// buildAWGConfig собирает конфигурацию сервера и выдаёт недостающие пары ключей и адреса пирам.
func buildAWGConfig(ib db.Inbound, users []db.User) (awg.Config, error) {
	s := proto.ParseSettings(ib.Settings)
	addr, err := proto.ServerAddr(firstNonEmpty(s.Subnet, "10.8.1.0/24"))
	if err != nil {
		return awg.Config{}, err
	}
	gm := db.GroupMap()
	data := db.ClientDataByInbound(ib.ID)
	var used []string
	for _, d := range data {
		if p, ok := proto.ParseAWGPeer(d); ok {
			used = append(used, p.IP)
		}
	}
	cfg := awg.Config{
		LogLevel: LoadCoreSettings().AWG.LogLevel,
		Name:     awgIface(ib.ID), Port: ib.Port, MTU: atoiDef(s.MTU, 1280), PrivateKey: s.PrivateKey, Address: addr,
		Params: awg.Params{Jc: s.Jc, Jmin: s.Jmin, Jmax: s.Jmax, S1: s.S1, S2: s.S2, S3: s.S3, S4: s.S4,
			H1: s.H1, H2: s.H2, H3: s.H3, H4: s.H4, I1: s.I1, I2: s.I2, I3: s.I3, I4: s.I4, I5: s.I5, HeaderProtectionKey: s.HeaderKey},
	}
	for _, u := range users {
		peer, ok := proto.ParseAWGPeer(data[u.ID])
		if !ok {
			// пирам выдаём данные всегда (даже неактивным), чтобы ссылка не менялась при включении
			np, err := proto.NewAWGPeer(firstNonEmpty(s.Subnet, "10.8.1.0/24"), used)
			if err != nil {
				return cfg, err
			}
			peer = np
			used = append(used, np.IP)
			_ = db.SetClientData(u.ID, ib.ID, np.JSON())
		}
		if u.Active() && db.Allowed(gm, u, ib.ID) {
			cfg.Peers = append(cfg.Peers, awg.Peer{PublicKey: peer.PublicKey, PSK: peer.PSK, AllowedIP: peer.IP + "/32"})
		}
	}
	return cfg, nil
}

// ApplyAWG запускает и обновляет серверы AmneziaWG по включённым подключениям.
func ApplyAWG() error {
	inbounds, err := db.GetInbounds()
	if err != nil {
		return err
	}
	users, _ := db.GetUsers()
	awgMu.Lock()
	defer awgMu.Unlock()
	if runtime.GOOS != "linux" {
		for _, ib := range inbounds {
			if ib.Enable && (ib.Kind == string(proto.AWG) || ib.Kind == string(proto.AWG3)) {
				return fmt.Errorf("AmneziaWG работает только на Linux (на %s серверу AmneziaWG нужны ip, iptables и /dev/net/tun)", runtime.GOOS)
			}
		}
	}

	want := map[int]bool{}
	var firstErr error
	for _, ib := range inbounds {
		if !ib.Enable || (ib.Kind != string(proto.AWG) && ib.Kind != string(proto.AWG3)) {
			continue
		}
		want[ib.ID] = true
		cfg, err := buildAWGConfig(ib, users)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", ib.Tag, err)
			}
			continue
		}
		if srv := awgServers[ib.ID]; srv != nil {
			if sameAWG(srv.Config(), cfg) {
				if err := srv.Update(cfg); err != nil && firstErr == nil {
					firstErr = err
				}
				continue
			}
			srv.Close() // изменились порт, ключ или параметры – интерфейс пересоздаём
			delete(awgServers, ib.ID)
		}
		srv, err := awg.Start(cfg, nil)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", ib.Tag, err)
			}
			continue
		}
		awgServers[ib.ID] = srv
	}
	for id, srv := range awgServers {
		if !want[id] {
			srv.Close()
			delete(awgServers, id)
		}
	}
	return firstErr
}

// sameAWG: совпадают ли параметры, требующие пересоздания интерфейса (без списка пиров).
func sameAWG(a, b awg.Config) bool {
	a.Peers, b.Peers = nil, nil
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func awgRunning() bool {
	awgMu.Lock()
	defer awgMu.Unlock()
	return len(awgServers) > 0
}

func stopAWG() {
	awgMu.Lock()
	defer awgMu.Unlock()
	for id, srv := range awgServers {
		srv.Close()
		delete(awgServers, id)
	}
}
