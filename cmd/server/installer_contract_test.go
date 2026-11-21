package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Установщик вызывает команды программы (`kitsune cli init`, `cli setup` и т.д.). Если команду переименовали или забыли
// добавить в меню, установка падает уже у пользователя – поэтому сверяем список заранее.
func TestInstallerCallsOnlyExistingCommands(t *testing.T) {
	script, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Skip("нет scripts/install.sh")
	}
	menu, err := os.ReadFile("menu.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`kitsune cli ([a-z0-9-]+)`)
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(script), -1) {
		seen[m[1]] = true
	}
	if len(seen) == 0 {
		t.Fatal("в установщике не нашлось вызовов kitsune cli – проверка устарела")
	}
	for cmd := range seen {
		if !strings.Contains(string(menu), `case "`+cmd+`"`) {
			t.Errorf("установщик вызывает `kitsune cli %s`, а такой команды в меню (menu.go) нет", cmd)
		}
	}
}
