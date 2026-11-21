package main

import (
	"bufio"
	"io"
	"os"
	"strings"
	"testing"
)

// runMenu прогоняет главное меню на заданном вводе и возвращает всё, что оно напечатало.
func runMenu(t *testing.T, input string) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Skip("нет канала")
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	menuLoopIn(bufio.NewReader(strings.NewReader(input)))
	w.Close()
	os.Stdout = old
	return <-done
}

const backText = "Press Enter to go back to the menu"

func TestBackPrompt(t *testing.T) {
	if !backPrompt(bufio.NewReader(strings.NewReader("\n"))) {
		t.Fatal("Enter должен возвращать в меню")
	}
	if backPrompt(bufio.NewReader(strings.NewReader(""))) {
		t.Fatal("конец ввода – выход")
	}
}

// После действия результат остаётся на экране до Enter: меню не печатается заново сразу.
func TestMenuWaitsAfterAction(t *testing.T) {
	out := runMenu(t, "99\n\n0\n") // неверный пункт, Enter, выход
	if strings.Count(out, backText) != 1 {
		t.Fatalf("подсказка «назад» должна быть один раз:\n%s", out)
	}
	i := strings.Index(out, "No such option")
	j := strings.Index(out, backText)
	k := strings.LastIndex(out, "Choose an option [0-18]")
	if i < 0 || j < i || k < j {
		t.Fatalf("порядок: результат, подсказка, только потом меню (i=%d j=%d k=%d)", i, j, k)
	}
}

// Пустой ввод и выход не требуют паузы.
func TestMenuNoPauseOnBlankAndExit(t *testing.T) {
	if out := runMenu(t, "\n0\n"); strings.Contains(out, backText) {
		t.Fatalf("пауза после пустого ввода:\n%s", out)
	}
	if out := runMenu(t, "0\n"); strings.Contains(out, backText) {
		t.Fatal("пауза при выходе")
	}
}

// Закрытый ввод (конец файла) после действия завершает меню без зависания.
func TestMenuEndsOnEOFAfterAction(t *testing.T) {
	out := runMenu(t, "99\n")
	if !strings.Contains(out, backText) {
		t.Fatalf("после действия нет подсказки:\n%s", out)
	}
}

// Пункт «Server tests» открывает подменю, «0. Back» возвращает в главное меню без паузы.
func TestMenuServerTestsOpensAndBacks(t *testing.T) {
	out := runMenu(t, "17\n0\n0\n")
	if !strings.Contains(out, "── Server tests") || !strings.Contains(out, "Choose an option [0-13]") {
		t.Fatalf("подменю не показано:\n%s", out)
	}
	if strings.Contains(out, backText) {
		t.Fatalf("пауза при возврате из подменю:\n%s", out)
	}
	if strings.Count(out, "Choose an option [0-18]") != 2 {
		t.Fatalf("главное меню должно показаться до входа и после возврата:\n%s", out)
	}
}

// Отказ от согласия: внешние запросы не выполняются, результат остаётся до Enter, подменю остаётся открытым.
func TestMenuServerTestsDeclinedConsent(t *testing.T) {
	out := runMenu(t, "17\n6\nno\n\n0\n0\n")
	if !strings.Contains(out, "ipinfo.io") || !strings.Contains(out, "Cancelled: external checks were not run") {
		t.Fatalf("нет запроса согласия или отмены:\n%s", out)
	}
	if strings.Contains(out, "Region and provider:") || strings.Count(out, backText) != 1 {
		t.Fatalf("внешний тест не должен запускаться; пауза один раз:\n%s", out)
	}
}

// Локальный тест запускается из подменю, показывает результат и ждёт Enter.
func TestMenuServerTestsRunsLocal(t *testing.T) {
	out := runMenu(t, "17\n5\n\n0\n0\n") // сетевые адреса: быстрый локальный тест
	if !strings.Contains(out, "Network addresses:") || strings.Count(out, backText) != 1 {
		t.Fatalf("результат теста или подсказка:\n%s", out)
	}
}

func TestMenuServerTestsBadPort(t *testing.T) {
	out := runMenu(t, "17\n9\nabc\n\n0\n0\n")
	if !strings.Contains(out, "Not a port number") {
		t.Fatalf("ожидалась ошибка порта:\n%s", out)
	}
}
