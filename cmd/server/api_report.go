package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/version"
)

// Отчёт для поддержки: минимум сведений, чтобы разобрать жалобу «не работает». Панель его только собирает и показывает:
// никуда сама не отправляет, человек читает текст и решает, кому его передать. Секреты и адреса вычищаются.

var (
	reUUID   = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	reURL    = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s"'<>]+`)
	reIPv4   = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	reIPv6   = regexp.MustCompile(`(?i)(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,6}:(?:[0-9a-f]{1,4})?(?::[0-9a-f]{1,4}){0,5}`)
	reToken  = regexp.MustCompile(`\b[A-Za-z0-9_\-+=]{24,}\b`)
	reDomain = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b`)
	rePath   = regexp.MustCompile(`(/[A-Za-z._-][A-Za-z0-9._-]*){2,}`)
)

// filenameExt – «домены», которые на самом деле имена файлов: их не трогаем.
var filenameExt = map[string]bool{"log": true, "json": true, "db": true, "conf": true, "yaml": true, "yml": true, "sh": true, "go": true, "txt": true, "toml": true, "pid": true, "sock": true}

// redactReport убирает из текста всё, что позволяет найти сервер, человека или войти в подключение:
// ссылки, адреса, UUID, длинные токены и ключи, домены, пути на диске.
func redactReport(s string) string {
	s = reURL.ReplaceAllString(s, "<ссылка>")
	s = rePath.ReplaceAllString(s, "<путь>")
	s = reUUID.ReplaceAllString(s, "<uuid>")
	s = reIPv4.ReplaceAllString(s, "<ip>")
	s = reIPv6.ReplaceAllString(s, "<ip>")
	s = reToken.ReplaceAllString(s, "<ключ>")
	s = reDomain.ReplaceAllStringFunc(s, func(m string) string {
		i := strings.LastIndex(m, ".")
		if i >= 0 && filenameExt[strings.ToLower(m[i+1:])] {
			return m
		}
		return "<домен>"
	})
	return s
}

// tailLines возвращает последние n строк файла (читает не более 64 КБ с конца).
func tailLines(path string, n int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	const max = 64 << 10
	off := st.Size() - max
	if off < 0 {
		off = 0
	}
	buf := make([]byte, st.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && len(buf) > 0 {
		return nil
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if off > 0 && len(lines) > 0 {
		lines = lines[1:] // первая строка могла быть обрезана
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

func buildSupportReport() string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("Отчёт Kitsune для поддержки")
	w("Время: %s", time.Now().UTC().Format("2006-01-02 15:04 UTC"))
	w("Версия: %s, %s/%s", version.Version, runtime.GOOS, runtime.GOARCH)
	w("")
	w("Ядра:")
	for _, s := range core.Statuses() {
		st := "остановлено"
		if s.Running {
			st = fmt.Sprintf("работает %d с, перезапусков %d", s.Uptime, s.Restarts)
		}
		line := fmt.Sprintf("- %s: %s", s.Name, st)
		if s.LastErr != "" {
			line += "; последняя ошибка: " + s.LastErr
		}
		w("%s", line)
	}
	w("")
	w("Подключения (тип, порт, включено):")
	if ibs, err := db.GetInbounds(); err == nil {
		for _, ib := range ibs {
			w("- %s, порт %d, %v", ib.Kind, ib.Port, ib.Enable)
		}
		if len(ibs) == 0 {
			w("- нет")
		}
	}
	if users, err := db.GetUsers(); err == nil {
		w("")
		w("Пользователей: %d", len(users))
	}
	w("")
	hjob.mu.Lock()
	rep := hjob.report
	hjob.mu.Unlock()
	if rep == nil {
		w("Проверка здоровья: ещё не запускалась (запустите её во вкладке «Здоровье» и сформируйте отчёт снова).")
	} else {
		w("Проверка здоровья: проблем %d, предупреждений %d", rep.Bad, rep.Warn)
		for _, it := range rep.Items {
			if it.Level != "ok" {
				w("- [%s] %s", it.Level, it.Text)
			}
		}
	}
	// журналы ядер (не access: в нём адреса, куда ходят люди)
	files, _ := filepath.Glob(filepath.Join(core.LogDir, "*.log"))
	for _, f := range files {
		base := filepath.Base(f)
		if strings.Contains(base, "access") {
			continue
		}
		lines := tailLines(f, 25)
		if len(lines) == 0 {
			continue
		}
		w("")
		w("Журнал %s (последние строки):", base)
		for _, l := range lines {
			w("  %s", l)
		}
	}
	return redactReport(b.String())
}

// handleSupportReport отдаёт текст отчёта для предпросмотра; панель сама ничего никуда не отправляет.
func handleSupportReport(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"text": buildSupportReport()})
}
