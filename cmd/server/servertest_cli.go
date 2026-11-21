package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"kitsune/internal/servertest"
)

// cmdServerTest: kit test [--json] [--ru] – тесты сервера до развёртывания (процессор, память, диск, адреса).
// Тесты, которым нужны внешние сервисы, здесь не запускаются: они идут отдельной командой с согласием пользователя.
// Код возврата 1, если сводка «не подходит».
func cmdServerTest(a []string) {
	asJSON, lang, external, yes, port := false, servertestLang(), false, false, 0
	for i := 0; i < len(a); i++ {
		switch a[i] {
		case "--json":
			asJSON = true
		case "--ru":
			lang = servertest.RU
		case "--en":
			lang = servertest.EN
		case "--external":
			external = true
		case "--yes":
			yes = true
		case "--port":
			if i+1 >= len(a) {
				fmt.Fprintln(os.Stderr, "--port needs a number")
				os.Exit(2)
			}
			p, err := strconv.Atoi(a[i+1])
			if err != nil || p < 1 || p > 65535 {
				fmt.Fprintln(os.Stderr, "--port: a number from 1 to 65535")
				os.Exit(2)
			}
			port = p
			i++
		default:
			fmt.Fprintln(os.Stderr, "Usage: kit test [--json] [--ru|--en] [--external [--yes] [--port N]]")
			os.Exit(2)
		}
	}
	tests := servertest.Local()
	if external {
		if !confirmExternal(bufio.NewReader(os.Stdin), lang, yes) {
			fmt.Fprintln(os.Stderr, servertest.L(lang, "Отменено: внешние проверки не запущены.", "Cancelled: external checks were not run."))
			os.Exit(1)
		}
		n := servertest.DefaultNet()
		n.Port = port
		tests = append(tests, servertest.External(n)...)
		tests = append(tests, servertest.MoreExternal(n)...)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if !asJSON {
		if external {
			fmt.Println(servertest.L(lang, "Тесты сервера (локальные и внешние)", "Server tests (local and external)"))
		} else {
			fmt.Println(servertest.L(lang, "Тесты сервера (локальные, без внешних запросов)", "Server tests (local, no external requests)"))
		}
	}
	rep := servertest.Run(ctx, tests, lang, func(r servertest.Result) {
		if !asJSON {
			printTestResult(r)
		}
	})
	if asJSON {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Println()
		fmt.Println(testMark(servertest.Level(map[string]servertest.Level{"ok": servertest.OK, "caveats": servertest.Warn, "bad": servertest.Bad}[rep.Verdict])) + "  " + servertest.VerdictText(rep.Verdict, lang))
	}
	if !external && !asJSON {
		fmt.Println(servertest.L(lang, "Регион, репутация адреса и доступность из других регионов: kit test --external", "Region, address reputation and reachability from other regions: kit test --external"))
	}
	if rep.Verdict == "bad" {
		os.Exit(1)
	}
}

// confirmExternal показывает, что уйдёт во внешние сервисы, и просит согласие (yes – без вопроса, для скриптов).
func confirmExternal(in *bufio.Reader, l servertest.Lang, yes bool) bool {
	fmt.Println(servertest.L(l, "Внешние проверки обращаются к сторонним сервисам:", "External checks contact third-party services:"))
	fmt.Println("  ipinfo.io            " + servertest.L(l, "видит адрес вашего сервера (с него идёт запрос)", "sees your server's address (the request comes from it)"))
	fmt.Println("  lists service  " + servertest.L(l, "отдаёт файл списка", "serves a list file, your server's address is not sent"))
	fmt.Println("  api.globalping.io    " + servertest.L(l, "получает адрес сервера (и порт для --port), результат доступен по ссылке измерения", "receives the server address (and the --port port), the result is reachable by the measurement link"))
	if yes {
		return true
	}
	fmt.Print(servertest.L(l, "Продолжить? Введите yes: ", "Continue? Type yes: "))
	line, _ := in.ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "yes")
}

func testMark(l servertest.Level) string {
	m := map[servertest.Level]string{servertest.OK: "✓", servertest.Warn: "!", servertest.Bad: "✗", servertest.Info: "·", servertest.Skip: "-"}[l]
	if m == "" {
		m = "?"
	}
	if !colorOn() {
		return m
	}
	col := map[servertest.Level]string{servertest.OK: "\x1b[32m", servertest.Warn: "\x1b[33m", servertest.Bad: "\x1b[31m"}[l]
	if col == "" {
		return m
	}
	return col + m + "\x1b[0m"
}

func printTestResult(r servertest.Result) {
	line := testMark(r.Level) + "  " + r.Title
	if r.Detail != "" {
		line += ": " + r.Detail
	}
	fmt.Println(line)
	if r.Hint != "" {
		fmt.Println("   " + strings.TrimSpace(r.Hint))
	}
}
