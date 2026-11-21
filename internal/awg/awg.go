// Package awg – сервер AmneziaWG внутри панели на библиотеке amneziawg-go: туннельный интерфейс, обфускация
// заголовков (классический набор и AmneziaWG 3.1), пиры по одному на пользователя.
package awg

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// Params – параметры обфускации. Пустое значение не передаётся устройству (используется умолчание библиотеки).
type Params struct {
	Jc, Jmin, Jmax, S1, S2, S3, S4 string
	H1, H2, H3, H4                 string
	I1, I2, I3, I4, I5             string
	HeaderProtectionKey            string // hex, 32 байта (AmneziaWG 3.1)
}

type Peer struct {
	PublicKey string // base64
	PSK       string // base64, необязателен
	AllowedIP string // 10.8.1.2/32
}

type Config struct {
	Name       string
	Port       int
	MTU        int
	PrivateKey string // base64
	Address    string // адрес сервера в туннеле с маской, например 10.8.1.1/24
	Params     Params
	Peers      []Peer
	LogLevel   string // silent, error (по умолчанию), verbose
}

func b64hex(s string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != 32 {
		return "", errors.New("ключ WireGuard должен быть 32 байта в base64")
	}
	return hex.EncodeToString(raw), nil
}

// UAPI собирает конфигурацию в формате IPC устройства (ключи в hex).
func (c Config) UAPI() (string, error) {
	priv, err := b64hex(c.PrivateKey)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	w := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			fmt.Fprintf(&sb, "%s=%s\n", k, strings.TrimSpace(v))
		}
	}
	w("private_key", priv)
	w("listen_port", strconv.Itoa(c.Port))
	p := c.Params
	for _, kv := range [][2]string{{"jc", p.Jc}, {"jmin", p.Jmin}, {"jmax", p.Jmax}, {"s1", p.S1}, {"s2", p.S2}, {"s3", p.S3}, {"s4", p.S4},
		{"h1", p.H1}, {"h2", p.H2}, {"h3", p.H3}, {"h4", p.H4}, {"i1", p.I1}, {"i2", p.I2}, {"i3", p.I3}, {"i4", p.I4}, {"i5", p.I5},
		{"header_protection_key", p.HeaderProtectionKey}} {
		w(kv[0], kv[1])
	}
	sb.WriteString("replace_peers=true\n")
	for _, peer := range c.Peers {
		pub, err := b64hex(peer.PublicKey)
		if err != nil {
			return "", err
		}
		w("public_key", pub)
		if peer.PSK != "" {
			psk, err := b64hex(peer.PSK)
			if err != nil {
				return "", err
			}
			w("preshared_key", psk)
		}
		sb.WriteString("replace_allowed_ips=true\n")
		w("allowed_ip", peer.AllowedIP)
	}
	return sb.String(), nil
}

// Server – работающий туннель AmneziaWG.
type Server struct {
	mu   sync.Mutex
	dev  *device.Device
	cfg  Config
	tdev tun.Device
	undo func()
}

// Start создаёт устройство. Если tdev == nil, создаётся системный TUN (нужны права root) и настраивается сеть.
func Start(cfg Config, tdev tun.Device) (*Server, error) {
	uapi, err := cfg.UAPI()
	if err != nil {
		return nil, err
	}
	srv := &Server{cfg: cfg}
	if tdev == nil {
		tdev, err = tun.CreateTUN(cfg.Name, cfg.MTU)
		if err != nil {
			return nil, fmt.Errorf("не удалось создать интерфейс %s (нужны права root и /dev/net/tun): %w", cfg.Name, err)
		}
		srv.tdev = tdev
	}
	level := device.LogLevelError
	switch cfg.LogLevel {
	case "silent":
		level = device.LogLevelSilent
	case "verbose":
		level = device.LogLevelVerbose
	}
	logger := device.NewLogger(level, "awg "+cfg.Name+": ")
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("устройство отклонило настройки AmneziaWG: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	srv.dev = dev
	if srv.tdev != nil { // системный интерфейс: адрес, маршруты, NAT
		realName, _ := tdev.Name()
		undo, err := setupNetwork(realName, cfg)
		if err != nil {
			dev.Close()
			return nil, err
		}
		srv.undo = undo
	}
	return srv, nil
}

// Update применяет новую конфигурацию (пиры и параметры) без пересоздания интерфейса.
func (s *Server) Update(cfg Config) error {
	uapi, err := cfg.UAPI()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.dev.IpcSet(uapi); err != nil {
		return err
	}
	s.cfg = cfg
	return nil
}

func (s *Server) Config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.undo != nil {
		s.undo()
		s.undo = nil
	}
	if s.dev != nil {
		s.dev.Close()
		s.dev = nil
	}
}
