// Package importer переносит пользователей и подключения из других панелей (3x-ui, Marzban) в Kitsune.
// Чужая база только читается: файл копируется во временную папку и открывается в режиме «только чтение».
// Любой текст из чужой базы считается недоверенным: проверяется, чистится и никогда не исполняется.
package importer

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"modernc.org/sqlite"
	sqlite3lib "modernc.org/sqlite/lib"

	"kitsune/internal/proto"
)

// Ограничения против вредоносных и случайно огромных баз.
const (
	MaxFileSize     = 256 << 20 // байт
	MaxUsers        = 100000
	MaxInbounds     = 2000
	maxJSONBytes    = 1 << 20
	maxValueBytes   = 16 << 20 // предел длины одного значения в чужой базе (SQLITE_LIMIT_LENGTH)
	maxReadBytes    = 64 << 20 // сколько всего текста и blob можно прочитать из одной таблицы
	maxTraffic      = int64(1) << 60
	maxExpiryMs     = int64(253402300799000) // 9999-12-31
	maxNoteRunes    = 200
	maxIPLimit      = 100000
	maxDelayedMs    = int64(10 * 366 * 24 * 3600 * 1000) // отложенный старт – не больше 10 лет
	sqliteHeaderLen = 16
)

// readTimeout – сколько всего можно читать чужую базу. Дольше нельзя: вызывающий код держит блокировку импорта.
var readTimeout = 30 * time.Second

const (
	Source3XUI    = "3xui"
	SourceMarzban = "marzban"
	SourceXray    = "xray" // config.json Xray: только подключения
	// SourceMarzbanAPI – Marzban через его API (в отчёте источник называется «marzban»).
	SourceMarzbanAPI = "marzban-api"
)

// SrcUser – пользователь из источника в нейтральном виде.
type SrcUser struct {
	Name         string // как в источнике (email или username)
	SubID        string
	UUID         string
	Password     string // пароль Trojan, если есть
	Note         string
	TrafficLimit int64 // байты, 0 – без лимита
	Used         int64
	ExpiryMs     int64 // абсолютный срок, мс; 0 – бессрочно
	DelayedMs    int64 // отложенный старт: длительность в мс, срок отсчитается от импорта
	IPLimit      int
	Enable       bool
	Vision       bool
	Warnings     []string
}

// SrcInbound – подключение из источника.
type SrcInbound struct {
	Name       string
	Port       int
	Protocol   string
	Enable     bool
	Kind       proto.Kind // пусто – не поддерживается
	Settings   proto.Settings
	SkipReason string
	Warnings   []string
}

// Data – всё, что прочитано из источника.
type Data struct {
	Source   string
	Users    []SrcUser
	Inbounds []SrcInbound
	Notes    []string
}

type readCfg struct{ inPlace bool }

// ReadOpt – параметр чтения чужой базы.
type ReadOpt func(*readCfg)

// InPlace – файл уже временная копия, которой владеет вызывающий код (загрузка через панель): открыть на месте,
// без второй копии. Файл и всё, что рядом появится, вызывающий код удаляет сам.
func InPlace() ReadOpt { return func(c *readCfg) { c.inPlace = true } }

func newReadCfg(opts []ReadOpt) readCfg {
	var c readCfg
	for _, o := range opts {
		o(&c)
	}
	return c
}

// openCopy копирует базу (и её журнал WAL, если лежит рядом) во временную папку и открывает копию.
// Исходный файл не открывается на запись и не блокируется, остановка чужой панели не нужна.
func openCopy(ctx context.Context, path string, cfg readCfg) (*sql.DB, func(), error) {
	st, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, nil, errors.New("нет доступа к файлу базы")
		}
		return nil, nil, errors.New("файл базы не найден")
	}
	if !st.Mode().IsRegular() {
		return nil, nil, errors.New("файл базы не найден")
	}
	if st.Size() > MaxFileSize {
		return nil, nil, fmt.Errorf("файл больше %d МБ", MaxFileSize>>20)
	}
	if err := checkHeader(path); err != nil {
		return nil, nil, err
	}
	dst := path
	cleanup := func() {}
	if !cfg.inPlace {
		root, err := TempRoot()
		if err != nil {
			return nil, nil, errors.New("не удалось подготовить временную папку")
		}
		dir, err := os.MkdirTemp(root, "kitsune-import-")
		if err != nil {
			return nil, nil, err
		}
		_ = os.Chmod(dir, 0o700)
		cleanup = func() { _ = os.RemoveAll(dir) }
		dst = filepath.Join(dir, "src.db")
		for _, ext := range []string{"", "-wal"} {
			if ext != "" {
				if s, e := os.Stat(path + ext); e != nil || !s.Mode().IsRegular() || s.Size() > MaxFileSize {
					continue
				}
			}
			if err := copyFile(path+ext, dst+ext); err != nil {
				cleanup()
				if errors.Is(err, os.ErrPermission) {
					return nil, nil, errors.New("нет доступа к файлу базы")
				}
				return nil, nil, errors.New("не удалось прочитать файл базы")
			}
		}
	}
	esc := strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23").Replace(dst)
	d, err := sql.Open("sqlite", "file:"+esc+"?_pragma=query_only(1)&_pragma=trusted_schema(0)&_pragma=busy_timeout(3000)&_pragma=cell_size_check(1)&_pragma=mmap_size(0)")
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	d.SetMaxOpenConns(1)
	// Одно соединение на всё чтение: предел длины значения действует, пока оно живёт.
	if conn, err := d.Conn(ctx); err == nil {
		_, _ = sqlite.Limit(conn, sqlite3lib.SQLITE_LIMIT_LENGTH, maxValueBytes)
		_ = conn.Close()
	}
	closeAll := func() { _ = d.Close(); cleanup() }
	if err := d.PingContext(ctx); err != nil {
		closeAll()
		return nil, nil, errors.New("файл не открывается как база SQLite")
	}
	if err := checkSchema(ctx, d); err != nil {
		closeAll()
		return nil, nil, err
	}
	return d, closeAll, nil
}

// checkSchema пускает дальше только базы, где есть обычные таблицы и индексы. Виды, триггеры и виртуальные таблицы
// у настоящих 3x-ui и Marzban не встречаются, а в чужом файле могут скрыть запрос, который не заканчивается.
func checkSchema(ctx context.Context, d *sql.DB) error {
	rows, err := d.QueryContext(ctx, `SELECT 1 FROM sqlite_master WHERE type NOT IN ('table', 'index')
		OR (type = 'table' AND UPPER(COALESCE(sql, '')) LIKE 'CREATE VIRTUAL%') LIMIT 1`)
	if err != nil {
		return errors.New("файл не открывается как база SQLite")
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("в файле есть виды, триггеры или виртуальные таблицы: это не база 3x-ui или Marzban, импорт отклонён")
	}
	if rows.Err() != nil {
		return errors.New("файл не открывается как база SQLite")
	}
	return nil
}

func checkHeader(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return errors.New("нет доступа к файлу базы")
		}
		return errors.New("файл базы не найден")
	}
	defer f.Close()
	h := make([]byte, sqliteHeaderLen)
	if _, err := io.ReadFull(f, h); err != nil || string(h) != "SQLite format 3\x00" {
		return errors.New("это не файл SQLite")
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, io.LimitReader(in, MaxFileSize+1)); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// tableCols – столбцы таблицы (пусто, если таблицы нет).
func tableCols(ctx context.Context, d *sql.DB, table string) map[string]bool {
	out := map[string]bool{}
	// имя таблицы – только из наших констант
	rows, err := d.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt any
		if rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk) == nil {
			out[strings.ToLower(name)] = true
		}
	}
	return out
}

// selectRows читает перечисленные столбцы; отсутствующие приходят как nil. Строк не больше limit.
func selectRows(ctx context.Context, d *sql.DB, table string, have map[string]bool, want []string, orderBy string, limit int) ([]map[string]any, error) {
	parts := make([]string, len(want))
	for i, c := range want {
		if have[c] {
			parts[i] = c
		} else {
			parts[i] = "NULL"
		}
	}
	q := "SELECT " + strings.Join(parts, ", ") + " FROM " + table
	if orderBy != "" && have[orderBy] {
		q += " ORDER BY " + orderBy
	}
	rows, err := d.QueryContext(ctx, q+fmt.Sprintf(" LIMIT %d", limit+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, errors.New("чтение базы заняло слишком много времени и прервано")
		}
		if strings.Contains(err.Error(), "too big") {
			return nil, fmt.Errorf("в таблице %s есть значение больше %d МБ, импорт отклонён", table, maxValueBytes>>20)
		}
		return nil, errors.New("не удалось прочитать таблицу " + table)
	}
	defer rows.Close()
	var out []map[string]any
	var total int
	for rows.Next() {
		vals := make([]any, len(want))
		ptrs := make([]any, len(want))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			if strings.Contains(err.Error(), "too big") {
				return nil, fmt.Errorf("в таблице %s есть значение больше %d МБ, импорт отклонён", table, maxValueBytes>>20)
			}
			return nil, errors.New("повреждена таблица " + table)
		}
		for _, v := range vals {
			switch t := v.(type) {
			case string:
				total += len(t)
			case []byte:
				total += len(t)
			}
		}
		if total > maxReadBytes {
			return nil, fmt.Errorf("таблица %s слишком большая: прочитано больше %d МБ, импорт отклонён", table, maxReadBytes>>20)
		}
		m := make(map[string]any, len(want))
		for i, c := range want {
			m[c] = vals[i]
		}
		out = append(out, m)
		if len(out) > limit {
			return nil, fmt.Errorf("в таблице %s больше %d строк", table, limit)
		}
	}
	if err := rows.Err(); err != nil {
		if strings.Contains(err.Error(), "too big") {
			return nil, fmt.Errorf("в таблице %s есть значение больше %d МБ, импорт отклонён", table, maxValueBytes>>20)
		}
		if ctx.Err() != nil {
			return nil, errors.New("чтение базы заняло слишком много времени и прервано")
		}
		return nil, errors.New("повреждена таблица " + table)
	}
	return out, nil
}

func toInt(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case float64:
		if t > float64(maxTraffic)*4 || t < -float64(maxTraffic)*4 {
			return maxTraffic * 4
		}
		return int64(t)
	case bool:
		if t {
			return 1
		}
	case string:
		return parseIntLoose(t)
	case []byte:
		return parseIntLoose(string(t))
	}
	return 0
}

func parseIntLoose(s string) int64 {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	var n int64
	neg := false
	if strings.HasPrefix(s, "-") {
		neg, s = true, s[1:]
	}
	if s == "" || len(s) > 18 {
		return 0
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int64(r-'0')
	}
	if neg {
		return -n
	}
	return n
}

func toStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case int64:
		return fmt.Sprint(t)
	}
	return ""
}

func toBool(v any, def bool) bool {
	switch t := v.(type) {
	case nil:
		return def
	case bool:
		return t
	case int64:
		return t != 0
	case float64:
		return t != 0
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true", "1":
			return true
		case "false", "0":
			return false
		}
	}
	return def
}

// cleanText убирает управляющие и невидимые символы (включая направление письма), схлопывает пробелы, режет по длине.
func cleanText(s string, maxRunes int) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	space := false
	n := 0
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			space = b.Len() > 0
			continue
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r),
			unicode.Is(unicode.Co, r), r == utf8.RuneError:
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
			n++
		}
		if n >= maxRunes {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// mask прячет середину секрета: в отчёты и логи попадают только края.
func mask(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + "…" + s[len(s)-2:]
}
