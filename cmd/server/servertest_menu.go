package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"kitsune/internal/servertest"
)

// testsMenu – подменю «Server tests» главного меню kit: отдельные тесты и их наборы. Результат остаётся на экране до Enter,
// «0. Back» возвращает в главное меню. Тесты с внешними сервисами спрашивают согласие один раз за открытие меню.
func testsMenu(in *bufio.Reader) {
	consented := false
	// ext возвращает true, если можно обращаться к внешним сервисам (согласие спрашивается один раз).
	ext := func() bool {
		if !consented {
			consented = confirmExternal(in, servertestLang(), false)
			if !consented {
				fmt.Println(tr("✗  Cancelled: external checks were not run.", "✗  Отменено: внешние проверки не запущены."))
			}
		}
		return consented
	}
	for {
		fmt.Print(paint(testsMenuText()))
		fmt.Print(tr("Choose an option [0-13]: ", "Выберите пункт [0-13]: "))
		line, err := in.ReadString('\n')
		if err != nil {
			fmt.Println()
			return
		}
		var ids []string
		external, port := false, 0
		switch strings.TrimSpace(line) {
		case "0", "q":
			return
		case "":
			continue
		case "1":
			ids = []string{"cpu", "memory", "disk", "addresses"}
		case "2":
			ids = []string{"cpu"}
		case "3":
			ids = []string{"memory"}
		case "4":
			ids = []string{"disk"}
		case "5":
			ids = []string{"addresses"}
		case "6":
			ids, external = []string{"region"}, true
		case "7":
			ids, external = []string{"reputation"}, true
		case "8":
			ids, external = []string{"reach_region"}, true
		case "9":
			fmt.Print(tr("Server port to check (1-65535): ", "Порт сервера для проверки (1-65535): "))
			p, _ := in.ReadString('\n')
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || n < 1 || n > 65535 {
				fmt.Println(tr("✗  Not a port number", "✗  Это не номер порта"))
				if !backPrompt(in) {
					return
				}
				continue
			}
			ids, external, port = []string{"reach_region"}, true, n
		case "10":
			ids, external = []string{"regional"}, true
		case "11":
			ids, external = []string{"speed"}, true
		case "12":
			ids, external = []string{"sni"}, true
		case "13":
			ids, external = []string{"cpu", "memory", "disk", "addresses", "region", "reputation", "reach_region", "regional", "speed"}, true
		default:
			fmt.Println(tr("✗  No such option", "✗  Нет такого пункта"))
			if !backPrompt(in) {
				return
			}
			continue
		}
		if external && !ext() {
			if !backPrompt(in) {
				return
			}
			continue
		}
		runTestIDs(ids, port)
		if !backPrompt(in) {
			return
		}
	}
}

// runTestIDs запускает выбранные тесты по их идентификаторам (в порядке ids) и печатает результаты и сводку.
func runTestIDs(ids []string, port int) {
	n := servertest.DefaultNet()
	n.Port = port
	pool := append(servertest.Local(), servertest.External(n)...)
	pool = append(pool, servertest.MoreExternal(n)...)
	pool = append(pool, servertest.SNITest(n))
	var picked []servertest.Test
	for _, id := range ids {
		for _, t := range pool {
			if t.ID == id {
				picked = append(picked, t)
			}
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fmt.Println()
	rep := servertest.Run(ctx, picked, servertestLang(), printTestResult)
	if len(picked) > 1 {
		fmt.Println()
		fmt.Println(testMark(map[string]servertest.Level{"ok": servertest.OK, "caveats": servertest.Warn, "bad": servertest.Bad}[rep.Verdict]) + "  " + servertest.VerdictText(rep.Verdict, servertestLang()))
	}
}
