package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"kitsune/internal/core"
	"kitsune/internal/db"
)

// runCLI выполняет служебные команды (установка ядер без запуска панели). Возвращает true, если команда обработана.
func runCLI(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "install-cores":
		installCores(args[1:])
		return true
	case "init": // создаёт базу и учётные данные администратора (печатает логин и пароль) – первым шагом установки
		db.InitDB()
		return true
	case "setup": // создание подключений и пользователя при установке
		cmdSetup(args[1:])
		return true
	case "sni":
		cmdSNI(args[1:])
		return true
	case "selfsteal":
		cmdSelfSteal(args[1:])
		return true
	case "cli": // консольное меню: вызывается командой kit
		runConsole(args[1:])
		return true
	}
	return false
}

// installCores скачивает ядра (с проверкой SHA-256) в ./bin. Без аргументов – набор по умолчанию для этой системы.
func installCores(names []string) {
	all := map[string]func() error{
		"xray": core.InstallXray, "singbox": core.InstallSingbox, "mtg": core.InstallMTG,
		"mita": core.InstallMita, "telemt": core.InstallTelemt,
	}
	if len(names) == 0 {
		names = []string{"xray", "singbox", "mtg"}
		if runtime.GOOS == "linux" {
			names = append(names, "mita")
		}
	}
	desc := map[string]string{
		"xray":    "core for VLESS, VMess, Trojan, Shadowsocks 2022, Hysteria2",
		"singbox": "core for TUIC and NaiveProxy",
		"mtg":     "MTProto proxy for Telegram",
		"mita":    "Mieru server",
		"telemt":  "MTProto with personal secrets",
	}
	failed := 0
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		f, ok := all[n]
		if !ok {
			fmt.Fprintf(os.Stderr, "✗  unknown core %q (xray, singbox, mtg, mita, telemt)\n", n)
			failed++
			continue
		}
		fmt.Printf("…  %s – %s\n", n, desc[n])
		if err := f(); err != nil {
			fmt.Fprintf(os.Stderr, "✗  %s: %v\n", n, err)
			failed++
			continue
		}
		fmt.Printf("✓  %s installed\n", n)
	}
	if failed > 0 {
		os.Exit(1)
	}
}
