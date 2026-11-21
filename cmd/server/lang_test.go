package main

import (
	"bufio"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
)

func withLang(t *testing.T, l string) {
	t.Helper()
	oldL, oldM := curLang, langMode
	curLang, langMode = l, "auto"
	t.Cleanup(func() { curLang, langMode = oldL, oldM })
}

func capture(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Skip("нет канала")
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	f()
	w.Close()
	os.Stdout = old
	return <-done
}

func TestLocaleLang(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for _, c := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"русская локаль", map[string]string{"LANG": "ru_RU.UTF-8"}, langRU},
		{"заглавными", map[string]string{"LANG": "RU_RU.utf8"}, langRU},
		{"английская", map[string]string{"LANG": "en_US.UTF-8"}, langEN},
		{"немецкая – английский", map[string]string{"LANG": "de_DE.UTF-8"}, langEN},
		{"пусто – английский", map[string]string{}, langEN},
		{"LC_ALL главнее LANG", map[string]string{"LC_ALL": "C", "LANG": "ru_RU.UTF-8"}, langEN},
		{"LC_ALL русский поверх английского LANG", map[string]string{"LC_ALL": "ru_RU.UTF-8", "LANG": "en_US.UTF-8"}, langRU},
		{"LC_MESSAGES между ними", map[string]string{"LC_MESSAGES": "ru_RU.UTF-8", "LANG": "en_US.UTF-8"}, langRU},
	} {
		if got := localeLang(env(c.env)); got != c.want {
			t.Errorf("%s: %s, ожидалось %s", c.name, got, c.want)
		}
	}
}

func TestChooseLangPriority(t *testing.T) {
	for _, c := range []struct {
		envKit, setting, locale, wantLang, wantMode string
	}{
		{"ru", "en", langEN, langRU, "env"},     // переменная главнее всего
		{"EN", "ru", langRU, langEN, "env"},     // регистр не важен
		{"", "en", langRU, langEN, "en"},        // сохранённый выбор главнее локали
		{"", "ru", langEN, langRU, "ru"},        //
		{"", "auto", langRU, langRU, "auto"},    // auto – по локали
		{"", "", langEN, langEN, "auto"},        // ничего не задано
		{"xx", "bogus", langRU, langRU, "auto"}, // мусор игнорируется
		{"", "", "de", langEN, "auto"},          // чужая локаль – английский
	} {
		l, m := chooseLang(c.envKit, c.setting, c.locale)
		if l != c.wantLang || m != c.wantMode {
			t.Errorf("%+v: %s/%s", c, l, m)
		}
	}
}

func TestTr(t *testing.T) {
	withLang(t, langEN)
	if tr("a", "б") != "a" {
		t.Fatal("английский")
	}
	curLang = langRU
	if tr("a", "б") != "б" {
		t.Fatal("русский")
	}
}

func TestMainMenuBothLanguages(t *testing.T) {
	withLang(t, langEN)
	en := mainMenuText(true, "running", "1.2.3")
	curLang = langRU
	ru := mainMenuText(false, "работает", "1.2.3")
	for _, n := range []string{" 0.", " 8.", "10.", "17.", "18."} {
		if !strings.Contains(en, n) || !strings.Contains(ru, n) {
			t.Errorf("в меню нет пункта %q", n)
		}
	}
	if !strings.Contains(en, "Language: auto: English") || !strings.Contains(en, "Autostart: on") || !strings.Contains(en, "Service: running") {
		t.Errorf("английское меню:\n%s", en)
	}
	if !strings.Contains(ru, "Язык: авто: Русский") || !strings.Contains(ru, "Автозапуск: выкл") || !strings.Contains(ru, "Служба: работает") || !strings.Contains(ru, "версия 1.2.3") {
		t.Errorf("русское меню:\n%s", ru)
	}
}

// Меню целиком на русском: сообщение об ошибке, подсказка «назад» и приглашение.
func TestMenuInRussian(t *testing.T) {
	withLang(t, langRU)
	out := runMenu(t, "99\n\n0\n")
	for _, s := range []string{"Выберите пункт [0-18]", "Нет такого пункта", "Нажмите Enter, чтобы вернуться в меню", "Служба:"} {
		if !strings.Contains(out, s) {
			t.Errorf("нет %q:\n%s", s, out)
		}
	}
	if strings.Contains(out, "No such option") || strings.Contains(out, "Choose an option") {
		t.Errorf("остался английский текст:\n%s", out)
	}
}

func TestSubmenusInRussian(t *testing.T) {
	withLang(t, langRU)
	for in, want := range map[string]string{"14\n0\n0\n": "HTTPS панели", "15\n0\n0\n": "Безопасность панели", "17\n0\n0\n": "Тесты сервера", "18\n0\n0\n": "Автоматически"} {
		if out := runMenu(t, in); !strings.Contains(out, want) {
			t.Errorf("%q: нет %q:\n%s", in, want, out)
		}
	}
}

// Справка на русском описывает те же команды, что и английская.
func TestHelpCommandsMatch(t *testing.T) {
	withLang(t, langEN)
	en := capture(t, printHelp)
	curLang = langRU
	ru := capture(t, printHelp)
	var checked int
	for _, line := range strings.Split(en, "\n") {
		if len(line) > 2 && line[0] == ' ' && line[1] == ' ' && line[2] != ' ' {
			tok := strings.Fields(line)[0]
			if tok == "no" { // «no command» – описание запуска без команды
				continue
			}
			checked++
			if !strings.Contains(ru, "  "+tok) {
				t.Errorf("в русской справке нет команды %q", tok)
			}
		}
	}
	if checked < 20 {
		t.Fatalf("проверено команд: %d", checked)
	}
	if !strings.Contains(ru, "Использование") || !strings.Contains(ru, "lang [ru|en|auto]") {
		t.Error("русская справка")
	}
}

func TestLangMenuChoosesAndKeeps(t *testing.T) {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		t.Skip("нужны права root для записи настройки")
	}
	t.Chdir(t.TempDir())
	withLang(t, langEN)
	// выбор «Русский» сразу меняет язык и сохраняется
	var acted bool
	out := capture(t, func() { acted = langMenu(bufio.NewReader(strings.NewReader("2\n"))) })
	if !acted || curLang != langRU || langMode != langRU || !strings.Contains(out, "Язык: Русский") {
		t.Fatalf("после выбора: acted=%v lang=%s mode=%s\n%s", acted, curLang, langMode, out)
	}
	// после перезапуска kit язык читается из сохранённого значения (переменная не задана, локаль английская)
	t.Setenv("KIT_LANG", "")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "en_US.UTF-8")
	curLang, langMode = langEN, "auto"
	initLang()
	if curLang != langRU {
		t.Fatalf("сохранённый выбор не применился: %s", curLang)
	}
	// «Автоматически» возвращает выбор по локали
	capture(t, func() { langMenu(bufio.NewReader(strings.NewReader("1\n"))) })
	if curLang != langEN || langMode != "auto" {
		t.Fatalf("auto: %s/%s", curLang, langMode)
	}
	// 0 и мусор ничего не меняют
	if capture(t, func() { acted = langMenu(bufio.NewReader(strings.NewReader("0\n"))) }); acted {
		t.Fatal("«Назад» не должен считаться действием")
	}
}

func TestKitLangEnvWins(t *testing.T) {
	t.Chdir(t.TempDir())
	withLang(t, langEN)
	t.Setenv("KIT_LANG", "ru")
	t.Setenv("LANG", "en_US.UTF-8")
	initLang()
	if curLang != langRU || langMode != "env" {
		t.Fatalf("%s/%s", curLang, langMode)
	}
	if !strings.Contains(langLabel(), "KIT_LANG") {
		t.Errorf("подпись: %s", langLabel())
	}
}
