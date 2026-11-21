package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"kitsune/internal/acme"
	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/proto"
	"kitsune/internal/totp"

	"github.com/skip2/go-qrcode"
	"kitsune/internal/version"
)

const (
	svcName  = "kitsune"
	unitPath = "/etc/systemd/system/kitsune.service"
)

var addrRe = regexp.MustCompile(`(?m)^Environment=KITSUNE_ADDR=(\S*)$`)

// panelAddr – адрес панели из юнита systemd (так его задал установщик); по умолчанию :8080.
func panelAddr() string {
	if b, err := os.ReadFile(unitPath); err == nil {
		if m := addrRe.FindSubmatch(b); m != nil && len(m[1]) > 0 {
			return string(m[1])
		}
	}
	if v := os.Getenv("KITSUNE_ADDR"); v != "" {
		return v
	}
	return ":8080"
}

func panelPort() int {
	_, p, err := net.SplitHostPort(panelAddr())
	n, _ := strconv.Atoi(p)
	if err != nil || n == 0 {
		return 8080
	}
	return n
}

func publicIP() string {
	cl := &http.Client{Timeout: 4 * time.Second}
	if r, err := cl.Get("https://api.ipify.org"); err == nil {
		defer r.Body.Close()
		if b, _ := io.ReadAll(io.LimitReader(r.Body, 64)); net.ParseIP(strings.TrimSpace(string(b))) != nil {
			return strings.TrimSpace(string(b))
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ip, ok := a.(*net.IPNet); ok && ip.IP.To4() != nil && !ip.IP.IsLoopback() {
				return ip.IP.String()
			}
		}
	}
	return "SERVER-IP"
}

func systemctl(args ...string) (string, error) {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func serviceState() string {
	out, _ := systemctl("is-active", svcName)
	switch out {
	case "active":
		return tr("running", "работает")
	case "activating":
		return tr("starting or restarting (activating) – if it stays like this, check the log: kit log", "запускается или перезапускается (activating) – если так остаётся, посмотрите журнал: kit log")
	case "inactive", "failed", "deactivating":
		return tr("stopped (", "остановлена (") + out + ")"
	}
	return tr("not found", "не найдена")
}

func autostart() bool {
	out, _ := systemctl("is-enabled", svcName)
	return out == "enabled"
}

// notRoot – на Linux команда запущена не от root.
func notRoot(goos string, euid int) bool { return goos == "linux" && euid != 0 }

func requireRoot() bool {
	if notRoot(runtime.GOOS, os.Geteuid()) {
		fmt.Println(tr("✗  Root rights needed: run  sudo kit", "✗  Нужны права root: запустите  sudo kit"))
		return false
	}
	return true
}

// requireRootDB – для команд, которые читают или меняют базу панели: без root база недоступна.
func requireRootDB() bool {
	if notRoot(runtime.GOOS, os.Geteuid()) {
		fmt.Println(tr("✗  Root rights needed: the panel database is only open to root. Log in as root and run the command again.", "✗  Нужны права root: база панели открыта только ему. Зайдите как root и повторите команду."))
		if directCall {
			os.Exit(1) // команда из командной строки: код возврата не 0, чтобы скрипты видели отказ
		}
		return false
	}
	return true
}

func installScript() string {
	wd, _ := os.Getwd()
	return filepath.Join(wd, "install.sh")
}

// runConsole – консольное меню (как у x-ui): без аргументов открывает меню, с аргументом выполняет одну команду.
func runConsole(args []string) {
	initLang()
	if len(args) == 0 {
		menuLoop()
		return
	}
	directCall = true
	if !console(args[0], args[1:]) {
		fmt.Printf(tr("✗  Unknown command %q\n\n", "✗  Неизвестная команда %q\n\n"), args[0])
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	if curLang == langRU {
		fmt.Print(helpRU)
		return
	}
	fmt.Print(`Usage: kit [command]

  no command         open the menu
  status             service state, panel address
  start|stop|restart start, stop or restart the service
  log                last lines of the log
  enable|disable     autostart with the server
  url                panel address and login
  password [pass]    reset the admin password (no argument – random one)
  2fa on|off|status  two-factor login (on – enable now, asks for an app code)
  bbr on|off|status  TCP speed-up (BBR algorithm)
  path [show|new|off] secret panel path (the panel opens only through it)
  private on|off     panel only via SSH tunnel (only subscriptions are public)
  port <port>        change the panel port
  https              panel certificate: https ip | acme DOMAIN [email] | self | off | status
  setup              create connections and a user: --protocols reality,ws --sni auto --user name
  sni check|find     check a REALITY site / find a neighbour
  selfsteal DOMAIN   decoy site on your own domain for REALITY (or: off, status)
  test [--json] [--ru] [--external [--yes] [--port N]]   check a new server: CPU, memory, disk, addresses; --external adds region, address reputation, reachability from other regions, service access, speed (asks consent)
  lang [ru|en|auto]  interface language of kit (auto – by the system language)
  cores [cores]      download cores (xray, singbox, mtg, mita, telemt)
  update [file]      update Kitsune to the latest release (or from a binary file you uploaded)
  import xray FILE [--apply] [--update]
  uninstall          remove Kitsune
  version            show version
`)
}

func console(cmd string, a []string) bool {
	switch cmd {
	case "help", "-h", "--help":
		printHelp()
	case "version", "-v", "--version":
		fmt.Println("Kitsune", version.Version)
	case "status":
		cmdStatus()
	case "start", "stop", "restart":
		if requireRoot() {
			cmdService(cmd)
		}
	case "log":
		cmdLog()
	case "enable", "disable":
		if requireRoot() {
			cmdAutostart(cmd == "enable")
		}
	case "url":
		cmdURL()
	case "password":
		if requireRootDB() {
			cmdPassword(a)
		}
	case "2fa-off":
		if requireRootDB() {
			cmdTOTPOff()
		}
	case "2fa":
		if requireRootDB() {
			cmd2FA(a)
		}
	case "bbr":
		if requireRoot() {
			cmdBBR(a)
		}
	case "path":
		cmdPath(a)
	case "private":
		if requireRoot() {
			cmdPrivate(a)
		}
	case "port":
		if requireRoot() {
			cmdPort(a)
		}
	case "https":
		if requireRoot() {
			cmdHTTPS(a)
		}
	case "selfsteal":
		if requireRoot() {
			cmdSelfSteal(a)
		}
	case "lang":
		cmdLang(a)
	case "test": // тесты сервера до развёртывания (без внешних запросов)
		cmdServerTest(a)
	case "init": // первый шаг установки: создаёт базу и печатает логин и пароль администратора
		db.InitDB()
	case "uninstall-info":
		cmdUninstallInfo()
	case "setup":
		cmdSetup(a)
	case "sni":
		cmdSNI(a)
	case "cores":
		installCores(a)
	case "update":
		if requireRoot() {
			cmdUpdate(a)
		}
	case "import":
		if requireRoot() {
			_ = cmdImport(a) // ошибку cmdImport уже напечатал; меню не закрываем
		}
	case "uninstall":
		if requireRoot() {
			cmdUninstall()
		}
	default:
		return false
	}
	return true
}

// Фирменный рыжий цвет Kitsune для меню (только в терминале и без NO_COLOR).
func colorOn() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	st, err := os.Stdout.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func paint(menu string) string {
	if !colorOn() {
		return menu
	}
	orange := "\x1b[38;5;208m"
	if c := os.Getenv("COLORTERM"); c == "truecolor" || c == "24bit" {
		orange = "\x1b[38;2;255;122;61m"
	}
	const reset, bold, green, dim, red = "\x1b[0m", "\x1b[1m", "\x1b[32m", "\x1b[2m", "\x1b[31m"
	lines := strings.Split(menu, "\n")
	for i, l := range lines {
		switch {
		case strings.HasPrefix(l, "  _  ___ _"), strings.HasPrefix(l, " | |/ (_)"), strings.HasPrefix(l, " | ' /"), strings.HasPrefix(l, " | . \\"), strings.HasPrefix(l, " |_|\\_"):
			lines[i] = orange + bold + l + reset
		case strings.HasPrefix(strings.TrimSpace(l), "──"):
			lines[i] = orange + l + reset
		case strings.Contains(l, "Service: running"), strings.Contains(l, "Служба: работает"):
			lines[i] = green + l + reset
		case strings.HasPrefix(l, "  Service:"), strings.HasPrefix(l, "  Служба:"):
			lines[i] = red + l + reset // не «работает»: красным, а не цветом рамки меню, иначе остановка службы сливается с оформлением
		case strings.HasPrefix(strings.TrimSpace(l), "0. Exit"), strings.HasPrefix(strings.TrimSpace(l), "0. Выход"):
			lines[i] = dim + l + reset
		}
	}
	return strings.Join(lines, "\n")
}

func menuLoop() { menuLoopIn(bufio.NewReader(os.Stdin)) }

func menuLoopIn(in *bufio.Reader) {
	for {
		fmt.Print(paint(mainMenuText(autostart(), serviceState(), version.Version)))
		fmt.Print(tr("Choose an option [0-18]: ", "Выберите пункт [0-18]: "))
		line, err := in.ReadString('\n')
		if err != nil {
			fmt.Println()
			return
		}
		acted := true // после действия результат остаётся на экране, пока не нажмут Enter (иначе главное меню сразу его затрёт)
		switch strings.TrimSpace(line) {
		case "0", "q":
			return
		case "1":
			console("url", nil)
		case "2":
			console("password", nil)
		case "3":
			console("2fa-off", nil)
		case "4":
			fmt.Print(tr("New panel port (1-65535): ", "Новый порт панели (1-65535): "))
			p, _ := in.ReadString('\n')
			console("port", []string{strings.TrimSpace(p)})
		case "5":
			console("start", nil)
		case "6":
			console("stop", nil)
		case "7":
			console("restart", nil)
		case "8":
			console("status", nil)
		case "9":
			console("log", nil)
		case "10":
			if autostart() {
				console("disable", nil)
			} else {
				console("enable", nil)
			}
		case "11":
			fmt.Print(tr("Which cores (space-separated, Enter – default set): ", "Какие ядра (через пробел, Enter – набор по умолчанию): "))
			l, _ := in.ReadString('\n')
			console("cores", strings.Fields(l))
		case "12":
			fmt.Print(tr("Path to the new binary (Enter – download the latest version): ", "Путь к новому бинарнику (Enter – скачать последнюю версию): "))
			p, _ := in.ReadString('\n')
			if requireRoot() {
				if p = strings.TrimSpace(p); p == "" {
					cmdUpdate(nil)
				} else {
					cmdUpdate([]string{p})
				}
			}
		case "13":
			console("uninstall", nil)
			if !serviceInstalled() { // удалили – меню больше не нужно
				fmt.Println(tr("Kitsune removed. Menu closed.", "Kitsune удалён. Меню закрыто."))
				return
			}
		case "14":
			acted = httpsMenu(in)
		case "15":
			acted = securityMenu(in)
		case "16":
			importMenu(in)
		case "18":
			acted = langMenu(in)
		case "17":
			testsMenu(in)
			acted = false // подменю само держит результаты на экране и возвращает в главное меню
		case "":
			acted = false
		default:
			fmt.Println(tr("✗  No such option", "✗  Нет такого пункта"))
		}
		if acted && !backPrompt(in) {
			fmt.Println()
			return
		}
	}
}

// backPrompt ждёт Enter, чтобы показанный результат не исчез под повторно выведенным меню. false – ввод закончился.
func backPrompt(in *bufio.Reader) bool {
	fmt.Print(tr("\n  ← Press Enter to go back to the menu ", "\n  ← Нажмите Enter, чтобы вернуться в меню "))
	_, err := in.ReadString('\n')
	return err == nil
}

func cmdStatus() {
	fmt.Println(tr("Service:     ", "Служба:      "), serviceState())
	fmt.Println(tr("Autostart:   ", "Автозапуск:  "), tr(map[bool]string{true: "on", false: "off"}[autostart()], map[bool]string{true: "вкл", false: "выкл"}[autostart()]))
	fmt.Println(tr("Version:     ", "Версия:      "), version.Version)
	cmdURL()
	for _, c := range core.Components() {
		if c.Platform {
			st := tr("not installed", "не установлено")
			if c.Installed {
				st = tr("installed", "установлено")
			}
			fmt.Printf(tr("Core %-14s %s\n", "Ядро %-14s %s\n"), c.Title+":", st)
		}
	}
}

func cmdService(action string) {
	desc := map[string]string{"start": tr("Starting", "Запускаю"), "stop": tr("Stopping", "Останавливаю"), "restart": tr("Restarting", "Перезапускаю")}[action]
	fmt.Printf(tr("…  %s service %s\n", "…  %s службу %s\n"), desc, svcName)
	if out, err := systemctl(action, svcName); err != nil {
		fmt.Println("✗ ", out)
		return
	}
	time.Sleep(time.Second)
	fmt.Println(tr("✓  Service:", "✓  Служба:"), serviceState())
}

func cmdLog() {
	cmd := exec.Command("journalctl", "-u", svcName, "--no-pager", "-n", "40", "-o", "cat")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	_ = cmd.Run()
}

func cmdAutostart(on bool) {
	act, txt := "disable", tr("off", "выкл")
	if on {
		act, txt = "enable", tr("on", "вкл")
	}
	if out, err := systemctl(act, svcName); err != nil {
		fmt.Println("✗ ", out)
		return
	}
	fmt.Println(tr("✓  Autostart: ", "✓  Автозапуск: ") + txt)
}

func cmdURL() {
	quietInit()
	fmt.Println(tr("Panel:      ", "Панель:     "), panelURL())
	fmt.Println(tr("Login:      ", "Логин:      "), db.GetSetting("admin_username", "admin"))
	fmt.Println(tr("Password:   ", "Пароль:     "), knownPassword())
}

// pathSuffix – «/секретный-путь/» или пусто, если путь не задан.
func pathSuffix() string {
	if p := panelPath(); p != "" {
		return "/" + p + "/"
	}
	return ""
}

// panelURL – адрес, по которому панель открывается сейчас (с HTTPS, если он включён, и секретным путём).
func panelURL() string {
	cfg := core.LoadPanelTLS()
	ip := publicIP()
	base := ""
	switch cfg.Mode {
	case "acme", "acme-ip":
		base = fmt.Sprintf("https://%s:%d", cfg.Domain, cfg.Port)
	case "self", "custom":
		base = fmt.Sprintf("https://%s:%d", ip, cfg.Port)
	default:
		base = fmt.Sprintf("http://%s:%d", ip, panelPort())
	}
	if panelPrivate() {
		return "only via SSH tunnel (kit → 15 → 4 has a ready command)"
	}
	return base + pathSuffix()
}

// knownPassword: пароль хранится только в виде хеша, поэтому показываем тот, что записал установщик, если он ещё действует.
func knownPassword() string {
	if b, err := os.ReadFile("/root/kitsune-install.txt"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			for _, key := range []string{"Password:", "Пароль:"} { // файл мог записать установщик любой версии
				if i := strings.Index(l, key); i >= 0 {
					if cand := strings.TrimSpace(l[i+len(key):]); cand != "" && db.AdminPasswordIs(cand) {
						return cand
					}
				}
			}
		}
	}
	return "changed by you (forgot it? reset with: kit password)"
}

func randomPassword() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func cmdPassword(a []string) {
	quietInit()
	pw := randomPassword()
	if len(a) > 0 {
		pw = a[0]
		if len(pw) < 8 {
			fmt.Println(tr("✗  Password must be at least 8 characters", "✗  Пароль не короче 8 символов"))
			return
		}
	}
	user := db.GetSetting("admin_username", "admin")
	if err := db.UpdateAdminCredentials(user, pw); err != nil {
		fmt.Println("✗ ", err)
		return
	}
	fmt.Println(tr("✓  Admin password changed", "✓  Пароль администратора изменён"))
	fmt.Println("   Login   :", user)
	fmt.Println("   Password:", pw)
	fmt.Println(tr("   Write it down: it won't be shown again.", "   Запишите его: повторно он не покажется."))
}

func cmdTOTPOff() {
	quietInit()
	for _, k := range []string{"totp_enabled", "totp_secret", "totp_pending", "totp_last_step"} {
		_ = db.SetSetting(k, "")
	}
	fmt.Println(tr("✓  Two-factor login turned off (you can enable it again in the panel settings)", "✓  Двухфакторный вход выключен (включить снова можно в настройках панели)"))
}

func cmdPort(a []string) {
	if len(a) != 1 {
		fmt.Println(tr("✗  Give a port: kit port 9000", "✗  Укажите порт: kit port 9000"))
		return
	}
	p, err := strconv.Atoi(a[0])
	if err != nil || p < 1 || p > 65535 {
		fmt.Println(tr("✗  Port must be a number from 1 to 65535", "✗  Порт — число от 1 до 65535"))
		return
	}
	if p != panelPort() {
		if l, err := net.Listen("tcp", ":"+a[0]); err != nil {
			fmt.Printf(tr("✗  Port %d is in use\n", "✗  Порт %d занят\n"), p)
			return
		} else {
			l.Close()
		}
	}
	b, err := os.ReadFile(unitPath)
	if err != nil {
		fmt.Println(tr("✗  Service file not found:", "✗  Файл службы не найден:"), unitPath)
		return
	}
	nb := addrRe.ReplaceAll(b, []byte("Environment=KITSUNE_ADDR=:"+a[0]))
	if string(nb) == string(b) && !addrRe.Match(b) {
		fmt.Println(tr("✗  The service file has no panel address line", "✗  В файле службы нет строки с адресом панели"))
		return
	}
	fmt.Printf(tr("…  Writing port %d to the service file\n", "…  Записываю порт %d в файл службы\n"), p)
	if err := os.WriteFile(unitPath, nb, 0o644); err != nil {
		fmt.Println("✗ ", err)
		return
	}
	_, _ = systemctl("daemon-reload")
	if _, err := exec.LookPath("ufw"); err == nil {
		_ = exec.Command("ufw", "allow", a[0]+"/tcp").Run()
	}
	cmdService("restart")
	fmt.Printf(tr("✓  Panel is now on port %d: http://%s:%d\n", "✓  Панель теперь на порту %d: http://%s:%d\n"), p, publicIP(), p)
}

func runInstaller(args ...string) {
	script := installScript()
	if _, err := os.Stat(script); err != nil {
		fmt.Println("✗  Installer not found:", script, "– copy install.sh into the Kitsune folder")
		return
	}
	wd, _ := os.Getwd()
	cmd := exec.Command("bash", append([]string{script}, append(args, "--dir", wd)...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	_ = cmd.Run()
}

func cmdUpdate(a []string) {
	if len(a) == 0 { // без аргумента – последняя версия из релиза (адрес и подпись проверяет install.sh)
		runInstaller("update")
		return
	}
	runInstaller("update", "--binary", a[0])
}

func cmdUninstall() {
	runInstaller("uninstall")
	if !serviceInstalled() {
		os.Exit(0) // команда kit тоже удалена: продолжать нечего
	}
}

// serviceInstalled: есть ли файл службы Kitsune (после удаления его уже нет).
func serviceInstalled() bool {
	_, err := os.Stat(unitPath)
	return err == nil
}

// cmdHTTPS настраивает HTTPS панели: самоподписанный сертификат или Let's Encrypt по домену.
func cmdHTTPS(a []string) {
	quietInit()
	cfg := core.LoadPanelTLS()
	mode := "status"
	if len(a) > 0 {
		mode = a[0]
	}
	switch mode {
	case "status":
		fmt.Println("Panel HTTPS:", map[string]string{"off": "off", "self": "self-signed certificate", "acme": "Let's Encrypt", "acme-ip": "Let's Encrypt on IP", "custom": "custom certificate"}[cfg.Mode], "port", cfg.Port)
		if cfg.Mode == "acme" {
			fmt.Println("Domain:", cfg.Domain)
		}
		return
	case "off":
		cfg.Mode = "off"
	case "self":
		cfg.Mode, cfg.Redirect = "self", true
		if db.GetSetting("public_host", "") == "" {
			_ = db.SetSetting("public_host", publicIP())
		}
		fmt.Println("…  Turning on HTTPS with a self-signed certificate: traffic is encrypted,")
		fmt.Println("   but the browser will show a warning – a trusted certificate is only issued for a domain.")
	case "custom":
		if len(a) < 3 {
			fmt.Println("✗  Give the files: kit https custom /path/fullchain.pem /path/privkey.pem")
			return
		}
		crt, key := a[1], a[2]
		if abs, err := filepath.Abs(crt); err == nil {
			crt = abs
		}
		if abs, err := filepath.Abs(key); err == nil {
			key = abs
		}
		if _, err := tls.LoadX509KeyPair(crt, key); err != nil {
			fmt.Println(tr("✗  The certificate does not load:", "✗  Сертификат не загружается:"), err)
			os.Exit(1)
		}
		cfg.Mode, cfg.CertFile, cfg.KeyFile, cfg.Redirect = "custom", crt, key, true
		fmt.Println("…  Turning on HTTPS with your own certificate (renew the files yourself; restart: kit restart)")
	case "ip":
		ip := publicIP()
		if len(a) > 1 {
			ip = a[1]
		}
		if net.ParseIP(ip) == nil {
			fmt.Println(tr("✗  Could not detect the server IP: kit https ip 1.2.3.4", "✗  Не удалось определить IP сервера: kit https ip 1.2.3.4"))
			os.Exit(1)
		}
		fmt.Printf("…  Requesting a Let's Encrypt certificate for IP %s (short-lived, about 6 days, renews itself)\n", ip)
		fmt.Println(tr("   Port 80/tcp must be free and open from outside (at the host and in the firewall).", "   Порт 80/tcp должен быть свободен и открыт снаружи (у хостера и в фаерволе)."))
		stopped := false
		if heldByKitsune(80) { // порт 80 держит сама панель (продление сертификатов): на время проверки останавливаем её
			_, _ = systemctl("stop", svcName)
			stopped = true
		}
		if _, _, _, err := acme.IPFiles(ip, ""); err != nil {
			if stopped {
				_, _ = systemctl("start", svcName)
			}
			fmt.Println("✗ ", err)
			os.Exit(1)
		}
		cfg.Mode, cfg.Domain, cfg.Redirect = "acme-ip", ip, true
	case "acme":
		if len(a) < 2 {
			fmt.Println(tr("✗  Give a domain: kit https acme vpn.example.com [email]", "✗  Укажите домен: kit https acme vpn.example.com [email]"))
			return
		}
		d := strings.ToLower(strings.TrimSpace(a[1]))
		if net.ParseIP(d) != nil || !strings.Contains(d, ".") {
			fmt.Println("✗  A domain is needed, not an IP address: use  kit https ip  for an IP certificate")
			return
		}
		cfg.Mode, cfg.Domain, cfg.Redirect = "acme", d, true
		if len(a) > 2 {
			cfg.Email = a[2]
		}
		if ips, err := net.LookupHost(d); err != nil {
			fmt.Printf("!  Domain %s is not found in DNS yet: create an A record pointing to this server's IP, or the certificate won't be issued\n", d)
		} else if my := publicIP(); !contains(ips, my) {
			fmt.Printf("!  Domain %s points to %s, but this server is %s: check the A record\n", d, strings.Join(ips, ", "), my)
		}
		fmt.Println(tr("…  Turning on Let's Encrypt: port 80/tcp must be free for verification and open from outside", "…  Включаю Let's Encrypt: порт 80/tcp должен быть свободен для проверки и открыт снаружи"))
	default:
		fmt.Println(tr("✗  Mode: ip, self, acme DOMAIN, custom CERT KEY, off or status", "✗  Режим: ip, self, acme ДОМЕН, custom СЕРТИФИКАТ КЛЮЧ, off или status"))
		return
	}
	if v, err := strconv.Atoi(os.Getenv("KITSUNE_HTTPS_PORT")); err == nil && v > 1024 && v < 65536 {
		cfg.Port = v // the installer picks a random free port
	}
	if cfg.Port == 0 || cfg.Port == 80 || cfg.Port == panelPort() || inboundUsesPort(cfg.Port) {
		cfg.Port = 8443
		for inboundUsesPort(cfg.Port) || cfg.Port == panelPort() {
			cfg.Port += 1000
		}
	}
	if err := core.SavePanelTLS(cfg); err != nil {
		fmt.Println("✗ ", err)
		return
	}
	if _, err := exec.LookPath("ufw"); err == nil && cfg.Mode != "off" {
		_ = exec.Command("ufw", "allow", strconv.Itoa(cfg.Port)+"/tcp").Run()
		if cfg.Mode == "acme" {
			_ = exec.Command("ufw", "allow", "80/tcp").Run()
		}
	}
	if os.Getenv("KITSUNE_NO_RESTART") == "" {
		cmdService("restart")
	}
	if cfg.Mode == "off" {
		fmt.Printf(tr("✓  HTTPS is off: http://%s:%d%s\n", "✓  HTTPS выключен: http://%s:%d%s\n"), publicIP(), panelPort(), pathSuffix())
		return
	}
	host := publicIP()
	if cfg.Mode == "acme" || cfg.Mode == "acme-ip" {
		host = cfg.Domain
	}
	fmt.Printf(tr("✓  Panel over HTTPS: https://%s:%d%s\n", "✓  Панель по HTTPS: https://%s:%d%s\n"), host, cfg.Port, pathSuffix())
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

// inboundUsesPort: порт уже занят подключением из базы (TCP), панель HTTPS не должна с ним столкнуться.
func inboundUsesPort(port int) bool {
	inbounds, _ := db.GetInbounds()
	for _, ib := range inbounds {
		if ib.Port == port {
			if info, ok := proto.Get(proto.Kind(ib.Kind)); ok && info.Net != "udp" {
				return true
			}
		}
	}
	return false
}

// cmdUninstallInfo печатает, за чем нужно прибраться при удалении: порты, которые открывались для Kitsune, и сетевые
// настройки AmneziaWG. Строки: «PORT 443/tcp», «AWG_IFACE awg3», «AWG_SUBNET 10.8.1.0/24». Читает только базу.
func cmdUninstallInfo() {
	quietInit()
	seen := map[string]bool{}
	port := func(p int, n string) {
		k := fmt.Sprintf("%d/%s", p, n)
		if p > 0 && !seen[k] {
			seen[k] = true
			fmt.Println("PORT", k)
		}
	}
	port(panelPort(), "tcp")
	if t := core.LoadPanelTLS(); t.Mode != "off" && t.Mode != "" {
		port(t.Port, "tcp")
		if t.Mode == "acme" || t.Mode == "acme-ip" {
			port(80, "tcp")
		}
	}
	inbounds, _ := db.GetInbounds()
	for _, ib := range inbounds {
		info, ok := proto.Get(proto.Kind(ib.Kind))
		if !ok {
			continue
		}
		for _, n := range []string{"tcp", "udp"} {
			if info.Net == n || info.Net == "both" {
				port(ib.Port, n)
			}
		}
		if ib.Kind == string(proto.AWG) || ib.Kind == string(proto.AWG3) {
			fmt.Println("AWG_IFACE", fmt.Sprintf("awg%d", ib.ID))
			sub := proto.ParseSettings(ib.Settings).Subnet
			if sub == "" {
				sub = "10.8.1.0/24"
			}
			fmt.Println("AWG_SUBNET", sub)
		}
	}
}

// httpsMenu – понятный выбор сертификата для панели (вместо ввода команд).
func httpsMenu(in *bufio.Reader) bool {
	fmt.Print(paint(httpsMenuText()))
	fmt.Print(tr("Choose an option [0-5]: ", "Выберите пункт [0-5]: "))
	line, _ := in.ReadString('\n')
	switch strings.TrimSpace(line) {
	case "1":
		fmt.Println(tr("You need a domain that already points to this server (A record) and a free port 80.", "Нужен домен, который уже указывает на этот сервер (A-запись), и свободный порт 80."))
		fmt.Print(tr("Domain (e.g. vpn.example.com): ", "Домен (например, vpn.example.com): "))
		d, _ := in.ReadString('\n')
		if d = strings.TrimSpace(d); d != "" {
			console("https", []string{"acme", d})
		}
	case "2":
		fmt.Println(tr("Port 80 must be free and open from outside (at the host and in the firewall).", "Порт 80 должен быть свободен и открыт снаружи (у хостера и в файрволе)."))
		console("https", []string{"ip"})
	case "3":
		console("https", []string{"self"})
	case "4":
		console("https", []string{"off"})
	case "5":
		console("https", []string{"status"})
	default:
		return false // «0. Back» и пустой ввод: сразу в главное меню
	}
	return true
}

// quietInit открывает базу без служебных сообщений (для меню и команд kit они только мешают).
func quietInit() {
	log.SetOutput(io.Discard)
	db.InitDB()
	log.SetOutput(os.Stderr)
}

// ---- Безопасность панели ----

func cmdPath(a []string) {
	quietInit()
	mode := "show"
	if len(a) > 0 {
		mode = a[0]
	}
	switch mode {
	case "raw": // для скриптов: «/путь/» или пусто
		fmt.Print(pathSuffix())
	case "new":
		p := db.RandomSlug(10)
		_ = db.SetSetting("panel_path", p)
		fmt.Println(tr("✓  New secret path:", "✓  Новый секретный путь:"), "/"+p+"/")
		fmt.Println(tr("   The panel now opens only through it:", "   Панель теперь открывается только по нему:"), panelURL())
	case "off":
		_ = db.SetSetting("panel_path", "")
		fmt.Println(tr("✓  Secret path off: the panel opens at the usual address", "✓  Секретный путь выключен: панель открывается по обычному адресу"), panelURL())
	default:
		if pathSuffix() == "" {
			fmt.Println(tr("Secret path is off. To enable: kit path new", "Секретный путь выключен. Включить: kit path new"))
			return
		}
		fmt.Println(tr("Secret path:", "Секретный путь:"), pathSuffix())
		fmt.Println("Panel:         ", panelURL())
	}
}

func cmdPrivate(a []string) {
	quietInit()
	mode := "status"
	if len(a) > 0 {
		mode = a[0]
	}
	ip := publicIP()
	tunnel := fmt.Sprintf("ssh -N -L 8080:127.0.0.1:10380 root@%s", ip)
	switch mode {
	case "on":
		fmt.Println(tr("The panel will stop opening from the internet: only subscription links will stay public.", "Панель перестанет открываться из интернета: публичными останутся только ссылки подписок."))
		fmt.Println(tr("You will log in to the panel through an SSH tunnel. Make sure SSH login works for you.", "Входить в панель придётся через SSH-туннель. Убедитесь, что вход по SSH у вас работает."))
		if st, err := os.Stdin.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
			fmt.Print("Continue? [y/N]: ")
			ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" && a != "д" && a != "да" {
				fmt.Println(tr("Cancelled.", "Отменено."))
				return
			}
		}
		_ = db.SetSetting("panel_private", "1")
		fmt.Println(tr("✓  Panel is closed from the internet. How to get in:", "✓  Панель закрыта от интернета. Как зайти:"))
		fmt.Println(tr("   1) On your computer run:           ", "   1) На своём компьютере выполните: ") + tunnel)
		fmt.Println(tr("   2) Open in the browser:            http://localhost:8080", "   2) Откройте в браузере:           http://localhost:8080"))
		cmdService("restart")
	case "off":
		_ = db.SetSetting("panel_private", "")
		fmt.Println(tr("✓  Panel is open at the usual address again:", "✓  Панель снова открыта по обычному адресу:"), panelURL())
		cmdService("restart")
	default:
		if panelPrivate() {
			fmt.Println(tr("Panel is closed from the internet (SSH tunnel only).", "Панель закрыта от интернета (только через SSH-туннель)."))
			fmt.Println("Log in:  " + tunnel + "   then http://localhost:8080")
		} else {
			fmt.Println(tr("Panel is open at the usual address. To close: kit private on", "Панель открыта по обычному адресу. Закрыть: kit private on"))
		}
	}
}

// cmd2FA: kit 2fa on | off | status
func cmd2FA(a []string) {
	quietInit()
	mode := "status"
	if len(a) > 0 {
		mode = a[0]
	}
	on := db.GetSetting("totp_enabled", "") == "1"
	switch mode {
	case "off":
		cmdTOTPOff()
	case "on":
		if on {
			fmt.Println(tr("Two-factor login is already on.", "Двухфакторный вход уже включён."))
			return
		}
		secret, err := totp.NewSecret()
		if err != nil {
			fmt.Println("✗ ", err)
			os.Exit(1)
		}
		spaced := ""
		for i, r := range secret {
			if i > 0 && i%4 == 0 {
				spaced += " "
			}
			spaced += string(r)
		}
		fmt.Println(tr("Two-factor login", "Двухфакторный вход"))
		uri := totp.URI(secret, db.GetSetting("admin_username", "admin"), "Kitsune")
		fmt.Println("  1. Open an authenticator app or password manager (Google Authenticator, Aegis, 2FAS, Microsoft Authenticator, Apple Passwords).")
		fmt.Println("  2. Scan the QR code (if it won't scan – enlarge the window or reduce the terminal font):")
		fmt.Println(terminalQR(uri))
		fmt.Println("     Or add the key manually (type: time-based):")
		fmt.Println("       " + spaced)
		fmt.Println("     Or import link: " + uri)
		in := bufio.NewReader(os.Stdin)
		for try := 0; try < 3; try++ {
			fmt.Print("  3. Enter the 6-digit code from the app: ")
			code, _ := in.ReadString('\n')
			if step, ok := totp.Verify(secret, strings.TrimSpace(code), time.Now()); ok {
				_ = db.SetSetting("totp_secret", secret)
				_ = db.SetSetting("totp_last_step", strconv.FormatUint(step, 10))
				_ = db.SetSetting("totp_enabled", "1")
				_ = db.SetSetting("totp_pending", "")
				fmt.Println(tr("✓  Two-factor login is on: signing in to the panel now needs a code from the app.", "✓  Двухфакторный вход включён: для входа в панель теперь нужен код из приложения."))
				fmt.Println(tr("   If you lose your phone, run on the server:  kit 2fa off", "   Если потеряете телефон, выполните на сервере: kit 2fa off"))
				return
			}
			fmt.Println(tr("✗  Wrong code: check the time on your phone and try again.", "✗  Неверный код: проверьте время на телефоне и попробуйте снова."))
		}
		fmt.Println(tr("Failed. Try again later: kit 2fa on", "Не получилось. Повторите позже: kit 2fa on"))
		os.Exit(1)
	default:
		if on {
			fmt.Println(tr("Two-factor login: on", "Двухфакторный вход: включён"))
		} else {
			fmt.Println(tr("Two-factor login: off. To enable: kit 2fa on", "Двухфакторный вход: выключен. Включить: kit 2fa on"))
		}
	}
}

func securityMenu(in *bufio.Reader) bool {
	fmt.Print(paint(securityMenuText()))
	fmt.Print(tr("Choose an option [0-6]: ", "Выберите пункт [0-6]: "))
	line, _ := in.ReadString('\n')
	switch strings.TrimSpace(line) {
	case "1":
		console("path", nil)
	case "2":
		console("path", []string{"new"})
	case "3":
		console("path", []string{"off"})
	case "4":
		console("private", []string{"on"})
	case "5":
		console("private", []string{"off"})
	case "6":
		console("2fa", []string{"on"})
	default:
		return false
	}
	return true
}

// terminalQR рисует QR-код полублоками (две строки модулей в одной строке терминала).
func terminalQR(text string) string {
	q, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		return ""
	}
	q.DisableBorder = true
	bm := q.Bitmap()
	const quiet = 2
	n := len(bm)
	get := func(x, y int) bool { // true = тёмный модуль
		x, y = x-quiet, y-quiet
		return x >= 0 && y >= 0 && x < n && y < n && bm[y][x]
	}
	var b strings.Builder
	for y := 0; y < n+2*quiet; y += 2 {
		b.WriteString("     ")
		for x := 0; x < n+2*quiet; x++ {
			top, bot := get(x, y), get(x, y+1)
			// светлый фон: светлый модуль = закрашенный блок
			switch {
			case !top && !bot:
				b.WriteString("█")
			case !top && bot:
				b.WriteString("▀")
			case top && !bot:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

// ---- BBR ----

// Переменные, а не константы: тесты подменяют путь и вызовы sysctl.
var (
	bbrConf   = "/etc/sysctl.d/99-kitsune-bbr.conf"
	sysctlGet = func(key string) string {
		out, _ := exec.Command("sysctl", "-n", key).Output()
		return strings.TrimSpace(string(out))
	}
	sysctlExec = func(args ...string) error { return exec.Command("sysctl", args...).Run() }
)

// enableBBR пишет файл и применяет его; при ошибке убирает файл и возвращает прежние qdisc и алгоритм
// (sysctl -p мог применить только часть строк).
func enableBBR() error {
	prevQ, prevCC := sysctlGet("net.core.default_qdisc"), sysctlGet("net.ipv4.tcp_congestion_control")
	if err := os.WriteFile(bbrConf, []byte("net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n"), 0o644); err != nil {
		return err
	}
	err := sysctlExec("-p", bbrConf)
	if err != nil {
		_ = os.Remove(bbrConf)
		if prevQ != "" {
			_ = sysctlExec("-w", "net.core.default_qdisc="+prevQ)
		}
		if prevCC != "" {
			_ = sysctlExec("-w", "net.ipv4.tcp_congestion_control="+prevCC)
		}
	}
	return err
}

// disableBBR убирает файл и возвращает cubic; ошибка sysctl не скрывается (файл при этом уже удалён).
func disableBBR() error {
	if err := os.Remove(bbrConf); err != nil && !os.IsNotExist(err) {
		return err
	}
	return sysctlExec("-w", "net.ipv4.tcp_congestion_control=cubic")
}

func cmdBBR(a []string) {
	mode := "status"
	if len(a) > 0 {
		mode = a[0]
	}
	cur := sysctlGet("net.ipv4.tcp_congestion_control")
	switch mode {
	case "on":
		if cur == "bbr" {
			fmt.Println(tr("BBR is already on.", "BBR уже включён."))
			return
		}
		virt, _ := exec.Command("systemd-detect-virt", "-c").Output()
		if t := strings.TrimSpace(string(virt)); t != "" && t != "none" {
			fmt.Println("✗  Server runs in a container (" + t + "): kernel network settings can't be changed here.")
			return
		}
		_ = exec.Command("modprobe", "tcp_bbr").Run()
		if !strings.Contains(" "+sysctlGet("net.ipv4.tcp_available_congestion_control")+" ", " bbr ") {
			fmt.Println(tr("✗  This server's kernel does not support BBR.", "✗  Ядро этого сервера не поддерживает BBR."))
			return
		}
		if err := enableBBR(); err != nil {
			fmt.Println(tr("✗  Could not turn on BBR:", "✗  Не удалось включить BBR:"), err)
			return
		}
		fmt.Println(tr("✓  BBR is on. To turn off: kit bbr off", "✓  BBR включён. Выключить: kit bbr off"))
	case "off":
		if _, err := os.Stat(bbrConf); err != nil {
			fmt.Println("No BBR setting from Kitsune, nothing to change. Current algorithm:", cur)
			return
		}
		if err := disableBBR(); err != nil {
			fmt.Println("✗  The setting file is removed, but the algorithm could not be changed now:", err)
			fmt.Println("   After a reboot the server returns to its default algorithm.")
			return
		}
		fmt.Println(tr("✓  Setting removed, algorithm set back to cubic.", "✓  Настройка убрана, алгоритм возвращён на cubic."))
	default:
		fmt.Println(tr("TCP congestion control:", "Алгоритм управления перегрузкой TCP:"), cur)
		if cur != "bbr" {
			fmt.Println(tr("To enable BBR: kit bbr on", "Включить BBR: kit bbr on"))
		}
	}
}

// importMenu – пункт меню «Импорт»: сначала пробный прогон, запись только после подтверждения.
func importMenu(in *bufio.Reader) {
	if !requireRoot() {
		return
	}
	fmt.Print("Path to the Xray config.json: ")
	l, _ := in.ReadString('\n')
	path := strings.TrimSpace(l)
	if path == "" {
		fmt.Println(tr("✗  Cancelled", "✗  Отменено"))
		return
	}
	base := []string{"xray", path}
	if err := cmdImport(base); err != nil {
		return
	}
	fmt.Print("Import now? Connections that already exist: 1 – skip, 2 – update, Enter – cancel: ")
	l, _ = in.ReadString('\n')
	switch strings.TrimSpace(l) {
	case "1":
		_ = cmdImport(append(append([]string{}, base...), "--apply"))
	case "2":
		// Отчёт «обновить» отличается от отчёта «пропускать»: показываем его до записи и спрашиваем ещё раз.
		fmt.Println("\nDry run in update mode:")
		if err := cmdImport(append(append([]string{}, base...), "--update")); err != nil {
			return
		}
		fmt.Print("Import now in update mode? Type y to confirm, Enter – cancel: ")
		l, _ = in.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(l)) == "y" {
			_ = cmdImport(append(append([]string{}, base...), "--apply", "--update"))
		} else {
			fmt.Println(tr("Nothing was written.", "Ничего не записано."))
		}
	default:
		fmt.Println(tr("Nothing was written.", "Ничего не записано."))
	}
}
