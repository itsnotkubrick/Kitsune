package core

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"kitsune/internal/db"
	"kitsune/internal/proto"
)

// ---- MTProto (mtg) ----

var (
	mtgProcs = map[string]*Proc{}
	// Карту пишет ApplyAll (под applyMu), а читают обработчики HTTP (Statuses, anyRunning) и остановка панели: одновременные чтение и
	// запись карты в Go роняют процесс, поэтому доступ только через mtgProc, mtgList и mtgDrop.
	mtgMu sync.RWMutex
)

// mtgProc возвращает процесс по имени, создавая его при первом обращении.
func mtgProc(name string) *Proc {
	mtgMu.Lock()
	defer mtgMu.Unlock()
	p := mtgProcs[name]
	if p == nil {
		p = NewProc(name)
		mtgProcs[name] = p
	}
	return p
}

// mtgList – снимок процессов; вызывать методы процессов нужно уже без замка.
func mtgList() []*Proc {
	mtgMu.RLock()
	defer mtgMu.RUnlock()
	list := make([]*Proc, 0, len(mtgProcs))
	for _, p := range mtgProcs {
		list = append(list, p)
	}
	return list
}

// mtgDrop убирает из карты процессы, которых нет в want, и возвращает их имена с процессами (остановка уже без замка).
func mtgDrop(want map[string]bool) map[string]*Proc {
	mtgMu.Lock()
	defer mtgMu.Unlock()
	gone := map[string]*Proc{}
	for name, p := range mtgProcs {
		if !want[name] {
			gone[name] = p
			delete(mtgProcs, name)
		}
	}
	return gone
}

func MTGBinary() string { return FindBinary("mtg") }

func mtgConfig(ib db.Inbound, s proto.Settings) string {
	return mtgConfigWith(ib, s, LoadCoreSettings().MTG)
}

// mtgConfigWith собирает config.toml для mtg; параметры сверх умолчаний пишутся, только если их изменили.
func mtgConfigWith(ib db.Inbound, s proto.Settings, cs MTGSettings) string {
	bind := firstNonEmpty(s.Listen, "0.0.0.0")
	if proto.Routed(ib, PublicEnv()) {
		bind = "127.0.0.1"
		ib.Port = proto.InnerPort(ib.ID)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "secret = %q\n", s.Secret)
	fmt.Fprintf(&sb, "bind-to = %q\n", bind+":"+strconv.Itoa(ib.Port))
	fmt.Fprintf(&sb, "concurrency = %d\n", atoiDef(s.MTGConcurrency, 8192))
	fmt.Fprintf(&sb, "prefer-ip = %q\n", firstNonEmpty(s.PreferIP, "prefer-ipv4"))
	if cs.Debug {
		sb.WriteString("debug = true\n")
	}
	if cs.AllowFallbackUnknownDC {
		sb.WriteString("allow-fallback-on-unknown-dc = true\n")
	}
	if cs.ToleratTimeSkewness != "" {
		fmt.Fprintf(&sb, "tolerate-time-skewness = %q\n", cs.ToleratTimeSkewness)
	}
	sb.WriteString("auto-update = false\n\n[stats.prometheus]\nenabled = false\n")
	if cs.DNS != "" {
		fmt.Fprintf(&sb, "\n[network]\ndns = %q\n", cs.DNS)
	}
	if cs.TimeoutIdle != "" || cs.TimeoutHandshake != "" {
		sb.WriteString("\n[network.timeout]\n")
		if cs.TimeoutIdle != "" {
			fmt.Fprintf(&sb, "idle = %q\n", cs.TimeoutIdle)
		}
		if cs.TimeoutHandshake != "" {
			fmt.Fprintf(&sb, "handshake = %q\n", cs.TimeoutHandshake)
		}
	}
	if !cs.AntiReplay {
		sb.WriteString("\n[defense.anti-replay]\nenabled = false\n")
	}
	if !cs.Blocklist {
		sb.WriteString("\n[defense.blocklist]\nenabled = false\n")
	}
	return sb.String()
}

func atoiDef(v string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
		return n
	}
	return def
}

// ApplyMTG запускает по одному процессу mtg на каждое включённое MTProto-подключение и гасит лишние.
func ApplyMTG() error {
	inbounds, err := db.GetInbounds()
	if err != nil {
		return err
	}
	want := map[string]bool{}
	var firstErr error
	for _, ib := range inbounds {
		if !ib.Enable || ib.Kind != string(proto.MTProto) {
			continue
		}
		s0 := proto.ParseSettings(ib.Settings)
		if s0.Engine == "telemt" {
			users, _ := db.GetUsers()
			want["tlm-"+strconv.Itoa(ib.ID)] = true
			if err := applyTelemt(ib, users); err != nil && firstErr == nil {
				firstErr = err
			}
			continue
		}
		name := "mtg-" + strconv.Itoa(ib.ID)
		want[name] = true
		bin := MTGBinary()
		if bin == "" {
			if firstErr == nil {
				firstErr = errors.New("mtg не установлен (нужен для MTProto)")
			}
			continue
		}
		s := proto.ParseSettings(ib.Settings)
		path, _ := filepath.Abs(name + ".toml")
		if err := os.WriteFile(path, []byte(mtgConfig(ib, s)), 0o600); err != nil {
			return err
		}
		p := mtgProc(name)
		if err := p.Start(bin, []string{"run", path}, nil, ""); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for name, p := range mtgDrop(want) {
		p.Stop()
		_ = os.Remove(name + ".toml")
	}
	return firstErr
}

// ---- Mieru (mita, только Linux) ----

var MitaProc = NewProc("mita")

func MitaBinary() string { return FindBinary("mita") }

func mitaRunDir() string {
	d, _ := filepath.Abs(filepath.Join("run", "mita"))
	return d
}

// BuildMitaConfig – серверный конфиг mita (JSON, формат из документации Mieru).
func BuildMitaConfig(ib db.Inbound, users []db.User) proto.M {
	s := proto.ParseSettings(ib.Settings)
	protocol := strings.ToUpper(firstNonEmpty(s.Transport, "TCP"))
	binding := proto.M{"protocol": protocol}
	if pr := strings.TrimSpace(s.PortRange); pr != "" {
		binding["portRange"] = pr
	} else {
		binding["port"] = ib.Port
	}
	var us []proto.M
	gm := db.GroupMap()
	for _, u := range users {
		if u.Active() && db.Allowed(gm, u, ib.ID) {
			us = append(us, proto.M{"name": u.Name, "password": u.Password})
		}
	}
	if us == nil {
		us = []proto.M{}
	}
	cs := LoadCoreSettings().Mita
	cfg := proto.M{
		"portBindings": []proto.M{binding},
		"users":        us,
		"loggingLevel": cs.LoggingLevel,
		"mtu":          atoiDef(s.MTU, 1400),
	}
	// Блок dns по умолчанию не пишем: значение dualStack в mita 3.38.1 принимается только в строго своём написании
	// (список допустимых значений проверяется при сохранении), а неверное роняет демон.
	if cs.DNSDualStack != "" {
		cfg["dns"] = proto.M{"dualStack": cs.DNSDualStack}
	}
	if cs.UserHintMandatory {
		cfg["advancedSettings"] = proto.M{"userHintIsMandatory": true}
	}
	return cfg
}

// ApplyMita пишет конфиг и (пере)запускает mita. Поддерживается одно подключение Mieru.
func ApplyMita() error {
	inbounds, err := db.GetInbounds()
	if err != nil {
		return err
	}
	var target *db.Inbound
	for i := range inbounds {
		if inbounds[i].Enable && inbounds[i].Kind == string(proto.Mieru) {
			target = &inbounds[i]
			break
		}
	}
	if target == nil {
		MitaProc.Stop()
		return nil
	}
	bin := MitaBinary()
	if bin == "" {
		return errors.New("mita не установлена (нужна для Mieru, только Linux)")
	}
	users, _ := db.GetUsers()
	cfg := BuildMitaConfig(*target, users)
	path, _ := filepath.Abs("mita.json")
	if err := writeJSON(path, cfg); err != nil {
		return err
	}
	dir := mitaRunDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sock := filepath.Join(dir, "mita.sock")
	_ = os.Remove(sock) // сокет от прошлого запуска мешает демону и обманывает ожидание ниже
	env := []string{"MITA_CONFIG_JSON_FILE=" + path, "MITA_UDS_PATH=" + sock, "MITA_INSECURE_UDS=1", "MITA_LOG_NO_TIMESTAMP=1"}
	if err := MitaProc.Start(bin, []string{"run"}, env, ""); err != nil {
		return err
	}
	// демон поднимает сокет не сразу; затем просим его слушать порты
	go func() {
		for i := 0; i < 30; i++ {
			if _, err := os.Stat(sock); err == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		cmd := exec.Command(bin, "start")
		cmd.Env = append(os.Environ(), env...)
		_ = cmd.Run()
	}()
	return nil
}
