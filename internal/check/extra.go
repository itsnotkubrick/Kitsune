package check

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"kitsune/internal/db"
	"kitsune/internal/metrics"
	"kitsune/internal/proto"
	"kitsune/internal/update"
	"kitsune/internal/version"
)

// Дополнительные проверки: ресурсы, сеть, безопасность, обновления, резервные копии.

func checkResources(add adder) {
	const g = "Ресурсы сервера"
	snap, _ := metrics.Get()
	if !snap.Available {
		return
	}
	if snap.DiskTotal > 0 {
		pct := float64(snap.DiskUsed) / float64(snap.DiskTotal) * 100
		switch {
		case pct >= 95:
			add(g, Bad, fmt.Sprintf("Диск заполнен на %.0f%% – Xray и база могут перестать писать данные", pct), "")
		case pct >= 85:
			add(g, Warn, fmt.Sprintf("Диск заполнен на %.0f%%", pct), "")
		default:
			add(g, OK, fmt.Sprintf("Диск: занято %.0f%%", pct), "")
		}
	}
	if snap.MemTotal > 0 {
		pct := float64(snap.MemUsed) / float64(snap.MemTotal) * 100
		if pct >= 92 {
			add(g, Warn, fmt.Sprintf("Память занята на %.0f%% – возможны вылеты процессов", pct), "")
		} else {
			add(g, OK, fmt.Sprintf("Память: занято %.0f%%", pct), "")
		}
	}
	if snap.CPUs > 0 && snap.Load1 > float64(snap.CPUs)*2 {
		add(g, Warn, fmt.Sprintf("Высокая нагрузка: load average %.1f при %d ядрах", snap.Load1, snap.CPUs), "")
	} else if snap.CPUs > 0 {
		add(g, OK, fmt.Sprintf("Нагрузка в норме (load %.2f, ядер %d)", snap.Load1, snap.CPUs), "")
	}
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err == nil && rl.Cur < 4096 {
		add(g, Warn, fmt.Sprintf("Лимит открытых файлов процесса мал (%d) – при многих клиентах упрётся (LimitNOFILE в службе)", rl.Cur), "")
	}
}

func checkNetwork(add adder) {
	const g = "Сеть"
	t0 := time.Now()
	conn, err := net.DialTimeout("tcp", "1.1.1.1:443", 4*time.Second)
	if err != nil {
		add(g, Bad, "Нет исходящего соединения с интернетом (1.1.1.1:443) – клиентам некуда выходить", "")
	} else {
		conn.Close()
		add(g, OK, fmt.Sprintf("Исходящий интернет доступен (1.1.1.1:443, %d мс)", time.Since(t0).Milliseconds()), "")
	}
	t0 = time.Now()
	if _, err := net.LookupHost("cloudflare.com"); err != nil {
		add(g, Warn, "DNS на сервере не отвечает – проверьте /etc/resolv.conf", "")
	} else {
		add(g, OK, fmt.Sprintf("DNS работает (cloudflare.com, %d мс)", time.Since(t0).Milliseconds()), "")
	}
	if b, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control"); err == nil {
		if cc := strings.TrimSpace(string(b)); cc != "bbr" {
			add(g, Info, "Алгоритм TCP: "+cc+". BBR обычно заметно ускоряет канал (sysctl net.ipv4.tcp_congestion_control=bbr)", "")
		} else {
			add(g, OK, "Включён TCP BBR", "")
		}
	}
}

func checkFirewall(add adder) {
	const g = "Файрвол"
	if _, err := exec.LookPath("ufw"); err != nil || db.DB == nil {
		return
	}
	out, err := exec.Command("ufw", "status").Output()
	if err != nil || !strings.Contains(string(out), "Status: active") {
		return
	}
	inbounds, _ := db.GetInbounds()
	var blocked []string
	for _, ib := range inbounds {
		if !ib.Enable {
			continue
		}
		if !strings.Contains(string(out), strconv.Itoa(ib.Port)) {
			blocked = append(blocked, strconv.Itoa(ib.Port))
		}
	}
	if len(blocked) > 0 {
		add(g, Bad, "UFW включён, но не пропускает порты подключений: "+strings.Join(blocked, ", ")+" (ufw allow <порт>)", "")
		return
	}
	add(g, OK, "UFW пропускает порты всех включённых подключений", "")
}

func checkInboundsExtra(add adder) {
	const g = "Подключения"
	if db.DB == nil {
		return
	}
	inbounds, err := db.GetInbounds()
	if err != nil {
		return
	}
	netOf := func(ib db.Inbound) string {
		if info, ok := proto.Get(proto.Kind(ib.Kind)); ok {
			return info.Net
		}
		return "tcp"
	}
	clash := func(a, b string) bool { return a == "both" || b == "both" || a == b }
	for i, ib := range inbounds {
		if !ib.Enable {
			continue
		}
		for _, other := range inbounds[:i] {
			if other.Enable && other.Port == ib.Port && clash(netOf(ib), netOf(other)) {
				add(g, Bad, fmt.Sprintf("Порт %d занят двумя подключениями: %s и %s", ib.Port, other.Tag, ib.Tag), "")
			}
		}
		if ib.Port == 8080 {
			add(g, Bad, fmt.Sprintf("Подключение %s использует порт 8080 – это порт самой панели", ib.Tag), "")
		}
	}
}

func checkClientsExtra(add adder) {
	const g = "Клиенты"
	if db.DB == nil {
		return
	}
	users, err := db.GetUsers()
	if err != nil {
		return
	}
	now := time.Now().UnixMilli()
	soon := 0
	for _, u := range users {
		if u.Active() && u.ExpiryTime > now && u.ExpiryTime < now+3*24*3600*1000 {
			soon++
		}
	}
	if soon > 0 {
		add(g, Info, fmt.Sprintf("Срок доступа истекает в ближайшие 3 дня у пользователей: %d", soon), "")
	}
}

var weakPasswords = []string{"admin", "password", "123456", "12345678", "qwerty", "kitsune", "kitsune-dev", "admin123"}

func checkSecurity(add adder) {
	const g = "Безопасность"
	if db.DB == nil {
		return
	}
	weak := false
	for _, w := range weakPasswords {
		if db.AdminPasswordIs(w) {
			weak = true
			break
		}
	}
	if weak {
		add(g, Warn, "Пароль администратора известный и слабый – смените его в «Настройках»", "")
	} else {
		add(g, OK, "Пароль администратора не из списка известных", "")
	}
	if db.GetSetting("session_secret", "") == "" {
		add(g, Warn, "Ключ сессий не сгенерирован", "")
	}
	if _, key := update.Source(); key == "" {
		add(g, Info, "В этой сборке не задан ключ издателя: обновления проверяются только по SHA-256, без подписи", "")
	}
}

func checkBackup(add adder) {
	const g = "Резервные копии"
	if db.DB == nil {
		return
	}
	last, _ := strconv.ParseInt(db.GetSetting("last_backup", "0"), 10, 64)
	switch {
	case last == 0:
		add(g, Warn, "Резервной копии базы ещё не делали – клиенты и ключи не защищены от потери сервера", "backup")
	case time.Since(time.Unix(last, 0)) > 14*24*time.Hour:
		add(g, Warn, fmt.Sprintf("Последняя копия базы сделана %d дн. назад", int(time.Since(time.Unix(last, 0)).Hours()/24)), "backup")
	default:
		add(g, OK, "Резервная копия базы свежая", "")
	}
}

// PanelUpdate – как проверить версию панели; задаётся программой (обычный путь – ветка release, а не манифест).
var PanelUpdate func() (latest string, available bool, err error)

func checkUpdates(add adder) {
	const g = "Обновления"
	check := PanelUpdate
	if check == nil {
		check = func() (string, bool, error) {
			u, key := update.Source()
			info, err := update.Check(u, version.Version, key)
			if err != nil {
				return "", false, err
			}
			return info.Latest, info.Available, nil
		}
	}
	latest, available, err := check()
	if err != nil {
		add(g, Info, "Не удалось проверить обновления: "+err.Error(), "")
		return
	}
	if available {
		add(g, Warn, fmt.Sprintf("Доступна новая версия Kitsune %s (у вас %s) – обновите в «Настройках»", latest, version.Version), "")
		return
	}
	add(g, OK, "Установлена последняя версия Kitsune "+version.Version, "")
}

// MakeBackup копирует базу в ./backups и запоминает время. Возвращает путь копии.
func MakeBackup() (string, error) {
	if err := os.MkdirAll("backups", 0o700); err != nil {
		return "", err
	}
	dst := filepath.Join("backups", "kitsune-"+time.Now().Format("20060102-150405")+".db")
	// VACUUM INTO даёт согласованную копию без остановки панели.
	if _, err := db.DB.Exec("VACUUM INTO ?", dst); err != nil {
		return "", err
	}
	_ = os.Chmod(dst, 0o600)
	_ = db.SetSetting("last_backup", strconv.FormatInt(time.Now().Unix(), 10))
	return dst, nil
}
