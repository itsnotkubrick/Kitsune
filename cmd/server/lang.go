package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"

	"kitsune/internal/db"
	"kitsune/internal/servertest"
)

// Язык консоли kit: русский, если так настроена система (или выбрано вручную), иначе английский.
// Приоритет: переменная KIT_LANG (ru или en) → сохранённая настройка (команда kit lang, пункт меню) → локаль сеанса → английский.

const (
	langEN      = "en"
	langRU      = "ru"
	langSetting = "kit_lang" // ru, en или auto
)

var (
	curLang  = langEN
	langMode = "auto" // что выбрано: auto, ru или en
)

// localeLang определяет язык по локали: первая непустая из LC_ALL, LC_MESSAGES, LANG; «ru…» – русский, остальное – английский.
func localeLang(get func(string) string) string {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := strings.ToLower(strings.TrimSpace(get(k))); v != "" {
			if strings.HasPrefix(v, "ru") {
				return langRU
			}
			return langEN
		}
	}
	return langEN
}

// chooseLang выбирает язык и режим по приоритету: явная переменная, затем сохранённая настройка, затем локаль.
func chooseLang(envKit, setting, locale string) (lang, mode string) {
	switch strings.ToLower(strings.TrimSpace(envKit)) {
	case langRU, langEN:
		return strings.ToLower(strings.TrimSpace(envKit)), "env"
	}
	switch strings.ToLower(strings.TrimSpace(setting)) {
	case langRU, langEN:
		return strings.ToLower(strings.TrimSpace(setting)), strings.ToLower(strings.TrimSpace(setting))
	}
	if locale == langRU {
		return langRU, "auto"
	}
	return langEN, "auto"
}

// initLang вызывается при старте kit. Сохранённый выбор читается из базы только там, где доступ к ней разрешён (root на Linux), и только если база есть.
func initLang() {
	setting := ""
	if !notRoot(runtime.GOOS, os.Geteuid()) {
		if _, err := os.Stat("kitsune.db"); err == nil {
			quietInit()
			setting = db.GetSetting(langSetting, "")
		}
	}
	curLang, langMode = chooseLang(os.Getenv("KIT_LANG"), setting, localeLang(os.Getenv))
}

// tr возвращает текст на языке консоли.
func tr(en, ru string) string {
	if curLang == langRU {
		return ru
	}
	return en
}

// servertestLang – язык текстов тестов сервера.
func servertestLang() servertest.Lang {
	if curLang == langRU {
		return servertest.RU
	}
	return servertest.EN
}

func langName(l string) string {
	if l == langRU {
		return "Русский"
	}
	return "English"
}

// langLabel – что сейчас выбрано, для меню и команды kit lang.
func langLabel() string {
	switch langMode {
	case "env":
		return langName(curLang) + " (KIT_LANG)"
	case "auto":
		return tr("auto: ", "авто: ") + langName(curLang)
	}
	return langName(curLang)
}

// saveLang сохраняет выбор языка (ru, en, auto) и применяет его сразу.
func saveLang(v string) error {
	quietInit()
	if err := db.SetSetting(langSetting, v); err != nil {
		return err
	}
	curLang, langMode = chooseLang("", v, localeLang(os.Getenv))
	return nil
}

// cmdLang: kit lang [ru|en|auto] – показать или сменить язык консоли.
func cmdLang(a []string) {
	if len(a) == 0 {
		fmt.Println(tr("Language:", "Язык:"), langLabel())
		fmt.Println(tr("Change: kit lang ru | en | auto (auto – by the system locale)", "Сменить: kit lang ru | en | auto (auto – по языку системы)"))
		return
	}
	v := strings.ToLower(a[0])
	if v != langRU && v != langEN && v != "auto" {
		fmt.Println(tr("✗  Usage: kit lang ru | en | auto", "✗  Использование: kit lang ru | en | auto"))
		if directCall {
			os.Exit(2)
		}
		return
	}
	if !requireRootDB() {
		return
	}
	if err := saveLang(v); err != nil {
		fmt.Println("✗ ", err)
		return
	}
	fmt.Println(tr("✓  Language:", "✓  Язык:"), langLabel())
}

// langMenu – пункт меню «Язык». Возвращает true, если что-то выбрано (тогда результат остаётся на экране).
func langMenu(in *bufio.Reader) bool {
	fmt.Print(paint(tr(`
  ── Language ───────────────────────────
   1. Automatic (by the system language)
   2. Русский
   3. English
   0. Back
  ──────────────────────────────────────
`, `
  ── Язык ───────────────────────────────
   1. Автоматически (по языку системы)
   2. Русский
   3. English
   0. Назад
  ──────────────────────────────────────
`)))
	fmt.Println(tr("Now: ", "Сейчас: ") + langLabel())
	fmt.Print(tr("Choose an option [0-3]: ", "Выберите пункт [0-3]: "))
	line, _ := in.ReadString('\n')
	v := map[string]string{"1": "auto", "2": langRU, "3": langEN}[strings.TrimSpace(line)]
	if v == "" {
		return false
	}
	if !requireRootDB() {
		return true
	}
	if err := saveLang(v); err != nil {
		fmt.Println("✗ ", err)
		return true
	}
	fmt.Println(tr("✓  Language:", "✓  Язык:"), langLabel())
	return true
}
