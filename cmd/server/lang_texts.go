package main

import "fmt"

// Тексты меню kit на двух языках. Выбор делает tr: русский при curLang == langRU, иначе английский.

const logoKit = `
  _  ___ _
 | |/ (_) |_ ___ _   _ _ __   ___
 | ' /| | __/ __| | | | '_ \ / _ \
 | . \| | |_\__ \ |_| | | | |  __/
 |_|\_\_|\__|___/\__,_|_| |_|\___|
`

// mainMenuText – главное меню с текущими значениями (автозапуск, состояние службы, версия, язык).
func mainMenuText(autostartOn bool, state, ver string) string {
	on := tr(map[bool]string{true: "on", false: "off"}[autostartOn], map[bool]string{true: "вкл", false: "выкл"}[autostartOn])
	body := tr(`  ──────────────────────────────────────
   0. Exit
   1. Panel address and login
   2. Reset admin password
   3. Turn off two-factor login (2FA)
   4. Change panel port
  ── Service ─────────────────────────────
   5. Start
   6. Stop
   7. Restart
   8. Status
   9. Log
  10. Autostart: %s
  ── Maintenance ────────────────────────
  11. Download or update cores
  12. Update Kitsune
  13. Uninstall Kitsune
  14. Panel HTTPS (certificate)
  15. Panel security
  16. Import Xray config.json
  ── Diagnostics ───────────────────────
  17. Server tests: CPU, disk, region, address checks
  18. Language: %s
  ──────────────────────────────────────
  Service: %s  ·  version %s
`, `  ──────────────────────────────────────
   0. Выход
   1. Адрес панели и логин
   2. Сбросить пароль администратора
   3. Отключить двухфакторный вход (2FA)
   4. Сменить порт панели
  ── Служба ──────────────────────────────
   5. Запустить
   6. Остановить
   7. Перезапустить
   8. Состояние
   9. Журнал
  10. Автозапуск: %s
  ── Обслуживание ───────────────────────
  11. Скачать или обновить ядра
  12. Обновить Kitsune
  13. Удалить Kitsune
  14. HTTPS панели (сертификат)
  15. Безопасность панели
  16. Импорт config.json Xray
  ── Диагностика ────────────────────────
  17. Тесты сервера: процессор, диск, регион, проверки адреса
  18. Язык: %s
  ──────────────────────────────────────
  Служба: %s  ·  версия %s
`)
	return logoKit + fmt.Sprintf(body, on, langLabel(), state, ver)
}

const helpRU = `Использование: kit [команда]

  без команды        открыть меню
  status             состояние службы, адрес панели
  start|stop|restart запустить, остановить или перезапустить службу
  log                последние строки журнала
  enable|disable     автозапуск вместе с сервером
  url                адрес панели и логин
  password [пароль]  сбросить пароль администратора (без аргумента – случайный)
  2fa on|off|status  двухфакторный вход (on – включить сейчас, спросит код из приложения)
  bbr on|off|status  ускорение TCP (алгоритм BBR)
  path [show|new|off] секретный путь панели (панель открывается только по нему)
  private on|off     панель только через SSH-туннель (публичны только подписки)
  port <порт>        сменить порт панели
  https              сертификат панели: https ip | acme ДОМЕН [почта] | self | off | status
  setup              создать подключения и пользователя: --protocols reality,ws --sni auto --user имя
  sni check|find     проверить сайт для REALITY / найти соседа
  selfsteal ДОМЕН    сайт-заглушка на своём домене для REALITY (или: off, status)
  test [--json] [--ru] [--external [--yes] [--port N]]   проверить новый сервер: процессор, память, диск, адреса; --external добавляет регион, репутация адреса, доступность из других регионов, доступ к сервисам, скорость (спросит согласие)
  lang [ru|en|auto]  язык консоли (auto – по языку системы)
  cores [ядра]       скачать ядра (xray, singbox, mtg, mita, telemt)
  update [файл]      обновить Kitsune до последнего выпуска (или из загруженного вами файла)
  import xray FILE [--apply] [--update]
  uninstall          удалить Kitsune
  version            показать версию
`

func httpsMenuText() string {
	return tr(`
  ── Panel HTTPS ────────────────────────
   1. Certificate for a domain (Let's Encrypt)
   2. Certificate for an IP address (Let's Encrypt)
   3. Self-signed (the browser will warn)
   4. Turn off HTTPS
   5. Show current state
   0. Back
  ──────────────────────────────────────
`, `
  ── HTTPS панели ───────────────────────
   1. Сертификат для домена (Let's Encrypt)
   2. Сертификат для IP-адреса (Let's Encrypt)
   3. Самоподписанный (браузер предупредит)
   4. Выключить HTTPS
   5. Показать текущее состояние
   0. Назад
  ──────────────────────────────────────
`)
}

func securityMenuText() string {
	return tr(`
  ── Panel security ─────────────────────
   1. Secret path: show
   2. New secret path
   3. Turn off secret path
   4. Close panel from the internet (SSH tunnel only)
   5. Open panel again
   6. Turn on two-factor login (2FA)
   0. Back
  ──────────────────────────────────────
`, `
  ── Безопасность панели ────────────────
   1. Секретный путь: показать
   2. Новый секретный путь
   3. Выключить секретный путь
   4. Закрыть панель от интернета (только через SSH-туннель)
   5. Открыть панель снова
   6. Включить двухфакторный вход (2FA)
   0. Назад
  ──────────────────────────────────────
`)
}

func testsMenuText() string {
	return tr(`
  ── Server tests ───────────────────────
  Local (no external requests)
   1. Run all local tests
   2. CPU
   3. Memory
   4. Disk
   5. Network addresses
  External (ask for your consent first)
   6. Region and provider
   7. Address reputation
   8. Reachability from other regions (ping)
   9. Reachability from other regions on a port (TCP)
  10. Access to services from this server (regional restrictions)
  11. Download speed (by region)
  12. Find a REALITY masking site (scans neighbours /24)
  13. Run everything (except 12)
   0. Back
  ──────────────────────────────────────
`, `
  ── Тесты сервера ──────────────────────
  Локальные (без внешних запросов)
   1. Все локальные тесты
   2. Процессор
   3. Память
   4. Диск
   5. Сетевые адреса
  Внешние (сначала спросим согласие)
   6. Регион и провайдер
   7. Репутация адреса
   8. Доступность из других регионов (ping)
   9. Доступность из других регионов по порту (TCP)
  10. Доступ с этого сервера к сервисам (региональные ограничения)
  11. Скорость скачивания (по регионам)
  12. Найти сайт для маскировки REALITY (просматривает соседние адреса /24)
  13. Запустить всё (кроме 12)
   0. Назад
  ──────────────────────────────────────
`)
}
