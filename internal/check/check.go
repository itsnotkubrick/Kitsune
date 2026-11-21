// Package check – диагностика сервера (аналог kit check) и безопасные автоисправления (аналог kit fix).
package check

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/proto"
)

const (
	OK   = "ok"
	Warn = "warn"
	Bad  = "bad"
	Info = "info"
)

// Item – одна строка отчёта. Fix – код исправления (пусто, если чинить автоматически нечего).
type Item struct {
	Group  string `json:"group"`
	Level  string `json:"level"`
	Text   string `json:"text"`
	Fix    string `json:"fix,omitempty"`
	FixTip string `json:"fix_tip,omitempty"`
}

type Report struct {
	Items []Item    `json:"items"`
	Bad   int       `json:"bad"`
	Warn  int       `json:"warn"`
	Fixes []FixInfo `json:"fixes"` // доступные автоисправления без повторов
}

type FixInfo struct {
	Code string `json:"code"`
	Tip  string `json:"tip"`
}

// WithFixes дописывает в отчёт список доступных исправлений.
func (r Report) WithFixes() Report {
	r.Fixes = []FixInfo{}
	for _, c := range r.Plan() {
		r.Fixes = append(r.Fixes, FixInfo{Code: c, Tip: fixTipFor(c)})
	}
	return r
}

var fixTips = map[string]string{
	"svc:xray":    "Запустить ядро Xray",
	"config":      "Пересобрать config.json из базы и перезапустить Xray",
	"xray":        "Перезапустить ядро Xray (порты подключений не слушаются)",
	"perms":       "Вернуть права 600 на config.json и kitsune.db",
	"installxray": "Скачать и установить проверенную версию Xray",
	"ntp":         "Включить синхронизацию времени (timedatectl set-ntp true)",
	"backup":      "Сделать резервную копию базы в папку backups/",
}

// FixHooks – исправления, которым нужны возможности самой панели (смена сайта-прикрытия, пути входа).
// Регистрируются из main: пакет проверок не знает про остальную панель. Ключ – имя до двоеточия, аргумент – после него.
var FixHooks = map[string]func(arg string) (string, error){}

// fixTipFor – подсказка к коду исправления, в том числе к кодам с аргументом («sni:3»).
func fixTipFor(code string) string {
	if t, ok := fixTips[code]; ok {
		return t
	}
	switch name, _, _ := strings.Cut(code, ":"); name {
	case "sni":
		return "Подобрать другой сайт-прикрытие (TLS 1.3 и HTTP/2) и применить. Старые ссылки работают ещё 7 дней"
	case "udpfirst":
		return "Поставить UDP-подключения (Hysteria2, TUIC, AmneziaWG) первыми в подписках"
	case "certs":
		return "Перевести подключения с самоподписанным сертификатом на сертификат Let's Encrypt домена панели"
	case "panelpath":
		return "Задать секретный путь входа в панель. Адрес панели изменится: сохраните новый"
	}
	return ""
}

const (
	configPath = core.ConfigPath
	dbPath     = "kitsune.db"
)

func hasSystemd() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := exec.LookPath("systemctl")
	return err == nil
}

func Run() Report {
	var items []Item
	for _, s := range Steps() {
		items = append(items, s.Do()...)
	}
	return Build(items)
}

type adder func(group, level, text, fix string)

func checkServices(add adder) {
	const g = "Службы"
	bin := core.XrayBinary()
	if bin == "" {
		add(g, Bad, "Ядро Xray не установлено", "installxray")
		return
	}
	if out, err := exec.Command(bin, "version").Output(); err == nil {
		add(g, OK, strings.SplitN(string(out), "\n", 2)[0], "")
	}
	if core.XrayProc.Running() {
		add(g, OK, "Ядро Xray запущено", "")
	} else if st := core.XrayProc.Status(); st.LastErr != "" {
		add(g, Bad, "Ядро Xray не запущено: "+st.LastErr, "svc:xray")
	} else {
		add(g, Bad, "Ядро Xray не запущено", "svc:xray")
	}
}

func checkConfig(add adder) {
	const g = "Конфигурация"
	data, err := os.ReadFile(core.ConfigPath)
	if err != nil {
		add(g, Bad, "Нет файла "+core.ConfigPath, "config")
		return
	}
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		add(g, Bad, "config.json содержит ошибку JSON: "+err.Error(), "config")
		return
	}
	if err := core.TestXrayConfig(core.ConfigPath); err != nil {
		add(g, Bad, "Xray не принимает config.json: "+err.Error(), "config")
		return
	}
	add(g, OK, "config.json корректен", "")
}

func tcpListens(port int) bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 800*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func udpListens(port int) bool {
	if _, err := exec.LookPath("ss"); err == nil {
		out, err := exec.Command("ss", "-Hlun", fmt.Sprintf("sport = :%d", port)).Output()
		return err == nil && strings.TrimSpace(string(out)) != ""
	}
	if _, err := exec.LookPath("lsof"); err == nil { // macOS и системы без ss
		out, _ := exec.Command("lsof", "-nP", fmt.Sprintf("-iUDP:%d", port)).Output()
		return strings.TrimSpace(string(out)) != ""
	}
	return true // проверить нечем – не считаем ошибкой
}

func checkPorts(add adder) {
	const g = "Подключения"
	if db.DB == nil {
		return
	}
	inbounds, err := db.GetInbounds()
	if err != nil {
		return
	}
	if len(inbounds) == 0 {
		add(g, Info, "Подключений пока нет – создайте их во вкладке «Подключения»", "")
		return
	}
	for _, ib := range inbounds {
		if !ib.Enable {
			continue
		}
		info, _ := proto.Get(proto.Kind(ib.Kind))
		netw := "tcp"
		coreName := core.XrayProc.Name
		if info != nil {
			netw = info.Net
			coreName = info.Core
		}
		if ib.Kind == string(proto.Naive) && !hasActiveUsers() {
			add(g, Info, fmt.Sprintf("%s: NaiveProxy запустится, когда появится первый активный пользователь", ib.Tag), "")
			continue
		}
		var listens bool
		label := "tcp"
		port := ib.Port
		if proto.Routed(ib, core.PublicEnv()) {
			// режим «всё на 443»: снаружи подключение доступно через маршрутизатор, изнутри – на локальном порту
			port = 443
			listens = core.RouterRunning() && tcpListens(proto.InnerPort(ib.ID))
			if ib.Kind == string(proto.MTProto) {
				listens = core.RouterRunning() && tcpListens(proto.InnerPort(ib.ID))
			}
			name := fmt.Sprintf("%s (порт %d/tcp через маршрутизатор)", ib.Tag, port)
			if listens {
				add(g, OK, name+": порт слушается", "")
			} else {
				add(g, Bad, name+": маршрутизатор или локальное подключение не отвечает", "xray")
			}
			continue
		}
		switch netw {
		case "udp":
			listens, label = udpListens(port), "udp"
		case "both":
			listens, label = tcpListens(port) || udpListens(port), "tcp+udp"
		default:
			listens = tcpListens(port)
		}
		name := fmt.Sprintf("%s (порт %d/%s)", ib.Tag, port, label)
		switch {
		case listens:
			add(g, OK, name+": порт слушается", "")
		case coreName == core.XrayProc.Name || coreName == "xray":
			add(g, Bad, name+": порт не слушается", "xray")
		default:
			add(g, Bad, name+": порт не слушается (ядро "+coreName+")", "")
		}
	}
}

func checkDB(add adder) {
	const g = "База данных"
	if db.DB == nil {
		return
	}
	var res string
	if err := db.DB.QueryRow("PRAGMA quick_check").Scan(&res); err != nil || res != "ok" {
		add(g, Bad, "kitsune.db повреждена, восстановите её из резервной копии", "")
		return
	}
	add(g, OK, "kitsune.db цела", "")
}

func checkClients(add adder) {
	const g = "Клиенты"
	if db.DB == nil {
		return
	}
	users, err := db.GetUsers()
	if err != nil {
		return
	}
	over := 0
	for _, u := range users {
		if u.Enable && !u.Active() {
			over++
		}
	}
	if over > 0 {
		add(g, Info, fmt.Sprintf("Пользователей с истёкшим сроком или исчерпанным лимитом: %d – они отключены автоматически", over), "")
	} else {
		add(g, OK, "Все пользователи в пределах лимитов", "")
	}
}

func checkPerms(add adder) {
	const g = "Безопасность"
	var loose []string
	for _, f := range []string{configPath, dbPath} {
		if st, err := os.Stat(f); err == nil && st.Mode().Perm()&0o077 != 0 {
			loose = append(loose, f)
		}
	}
	if len(loose) > 0 {
		add(g, Warn, "Файлы с ключами и паролями доступны другим пользователям: "+strings.Join(loose, ", "), "perms")
		return
	}
	add(g, OK, "Права на config.json и kitsune.db – 600", "")
}

func checkTime(add adder) {
	const g = "Система"
	if !hasSystemd() {
		return
	}
	out, err := exec.Command("timedatectl", "show", "-p", "NTPSynchronized", "--value").Output()
	if err != nil {
		return
	}
	if strings.TrimSpace(string(out)) == "yes" {
		add(g, OK, "Время синхронизировано", "")
	} else {
		add(g, Warn, "Время не синхронизировано – из-за этого REALITY и Hysteria2 могут не подключаться", "ntp")
	}
}

// Plan – уникальные коды исправлений из отчёта.
func (r Report) Plan() []string {
	seen := map[string]bool{}
	var plan []string
	has := func(c string) bool {
		for _, it := range r.Items {
			if it.Fix == c {
				return true
			}
		}
		return false
	}
	for _, it := range r.Items {
		if it.Fix == "" || seen[it.Fix] {
			continue
		}
		// Пересборка конфига сама перезапускает Xray – отдельные перезапуски лишние.
		if (it.Fix == "xray" || it.Fix == "svc:xray") && has("config") {
			continue
		}
		seen[it.Fix] = true
		plan = append(plan, it.Fix)
	}
	return plan
}

// Apply выполняет одно исправление. rebuild пересобирает конфиги из базы (передаётся из main).
func Apply(code string, rebuild func() error) (string, error) {
	switch code {
	case "svc:xray", "xray":
		if err := rebuild(); err != nil {
			return "", err
		}
		time.Sleep(time.Second)
		return "Ядро Xray перезапущено", nil
	case "installxray":
		if err := core.InstallXray(); err != nil {
			return "", err
		}
		if err := rebuild(); err != nil {
			return "", err
		}
		return "Xray " + core.InstalledVersion("xray") + " установлен и запущен", nil
	case "config":
		if err := rebuild(); err != nil {
			return "", err
		}
		time.Sleep(2 * time.Second)
		return "config.json пересобран из базы", nil
	case "perms":
		for _, f := range []string{configPath, dbPath} {
			if _, err := os.Stat(f); err == nil {
				if err := os.Chmod(f, 0o600); err != nil {
					return "", err
				}
			}
		}
		return "Права 600 возвращены", nil
	case "backup":
		path, err := MakeBackup()
		if err != nil {
			return "", err
		}
		return "Копия базы сохранена: " + path, nil
	case "ntp":
		if err := exec.Command("timedatectl", "set-ntp", "true").Run(); err != nil {
			return "", fmt.Errorf("не удалось включить синхронизацию времени (поставьте systemd-timesyncd): %w", err)
		}
		return "Синхронизация времени включена", nil
	}
	if name, arg, _ := strings.Cut(code, ":"); FixHooks[name] != nil {
		return FixHooks[name](arg)
	}
	return "", fmt.Errorf("неизвестное исправление %q", code)
}

func hasActiveUsers() bool {
	users, _ := db.GetUsers()
	for _, u := range users {
		if u.Active() {
			return true
		}
	}
	return false
}
