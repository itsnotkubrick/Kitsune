package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/importer"
)

var importMu sync.Mutex // один импорт за раз

// importOptions – проверки порта с учётом служебных портов панели (подключения из базы проверяет сам импорт).
func importOptions(apply, update bool) importer.Options {
	return importer.Options{
		Apply: apply, Update: update,
		PortReserved: func(port int, netw string) bool {
			if port == 8080 || port == 10085 || reservedLocalPort(port) || port == panelPort() {
				return true
			}
			t := core.LoadPanelTLS()
			return t.Mode != "off" && t.Mode != "" && t.Port == port && netw != "udp"
		},
		PortListening: portListening,
	}
}

// importBackupsKeep – сколько последних копий before-import хранить.
const importBackupsKeep = 5

// pruneImportBackups удаляет самые старые копии before-import-*.db, остальные файлы в backups не трогает.
// Порядок – по метке времени в имени (часы и mtime могут быть неверными); копия current, созданная этим запуском, остаётся всегда.
func pruneImportBackups(keep int, current string) {
	m, _ := filepath.Glob(filepath.Join("backups", "before-import-*.db"))
	if len(m) <= keep {
		return
	}
	var names []string
	for _, p := range m {
		if st, err := os.Lstat(p); err == nil && st.Mode().IsRegular() {
			names = append(names, filepath.Base(p))
		}
	}
	// В имени метка YYYYMMDD-HHMMSS-наносекунды-pid: по возрастанию имён – от старых к новым.
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	if len(names) <= keep {
		return
	}
	// Оставляем keep самых новых; если текущей копии среди них нет (метка времени в имени отстаёт), она занимает последнее место.
	save := map[string]bool{current: true}
	for _, n := range names {
		if len(save) >= keep {
			break
		}
		save[n] = true
	}
	for _, n := range names {
		if !save[n] {
			_ = os.Remove(filepath.Join("backups", n))
		}
	}
}

// importRows – сколько строк каждого списка попадает в отчёт панели и консоли; итоги считаются по всем.
const importRows = 500

// loadImportSource читает базу источника из файла path; файл не изменяется.
// Для Marzban можно добавить config.json Xray (cfgPath): из него берутся подключения.
func loadImportSource(r importReq, opts ...importer.ReadOpt) (*importer.Data, error) {
	source, path, cfgPath := r.source, r.path, r.cfgPath
	switch source {
	case importer.SourceMarzbanAPI:
		ctx := r.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		return importer.ReadMarzbanAPI(ctx, r.apiURL, r.apiAuth)
	case importer.Source3XUI:
		return importer.Read3XUI(path, opts...)
	case importer.SourceMarzban:
		data, err := importer.ReadMarzban(path, opts...)
		if err != nil || cfgPath == "" {
			return data, err
		}
		cfg, err := importer.ReadXrayConfig(cfgPath)
		if err != nil {
			return nil, err
		}
		data.WithConfig(cfg)
		return data, nil
	case importer.SourceXray:
		return importer.ReadXrayConfig(path)
	}
	return nil, errors.New("неизвестный источник: выберите 3x-ui, Marzban, Marzban через API или config.json Xray")
}

// importReq – параметры общего запуска импорта.
type importReq struct {
	source, path  string
	cfgPath       string           // config.json Xray к базе Marzban (необязательно)
	apiURL        string           // адрес Marzban для источника marzban-api
	apiAuth       importer.APIAuth // токен или логин с паролем: только в памяти на время запуска
	apply, update bool
	upload        bool            // файл – наша временная копия из панели: читается на месте, без второй копии
	ctx           context.Context // отмена чтения по API, когда запрос панели закрыт (пусто – без отмены)
	applyCores    bool            // применить ядра в этом процессе (только процесс панели; консоль после записи просит kit restart)
}

// runImport – общая часть панели и консоли. При apply сначала делает копию базы Kitsune, потом пишет одной транзакцией.
// В панели затем применяет ядра; в консоли только синхронизирует членство: процесс консоли не должен перезапускать
// Xray панели и занимать порты. Возвращает отчёт, имя файла копии и предупреждение.
// Чтение чужой базы ограничено по времени, поэтому блокировка не держится дольше этого срока.
func runImport(r importReq) (rep *importer.Report, backupName, warn string, err error) {
	importMu.Lock()
	defer importMu.Unlock()
	return runImportLocked(r)
}

// runImportLocked – то же, но importMu уже занят вызывающим кодом (панель берёт его до приёма файла).
func runImportLocked(r importReq) (rep *importer.Report, backupName, warn string, err error) {
	var ro []importer.ReadOpt
	if r.upload {
		ro = append(ro, importer.InPlace())
	}
	data, err := loadImportSource(r, ro...)
	if err != nil {
		return nil, "", "", err
	}
	if r.apply {
		if err := os.MkdirAll("backups", 0o700); err != nil {
			return nil, "", "", errors.New("не удалось создать папку для копии базы")
		}
		_ = os.Chmod("backups", 0o700) // папка могла остаться с прежними правами
		now := time.Now()
		backupName = fmt.Sprintf("before-import-%s-%09d-%d.db", now.Format("20060102-150405"), now.Nanosecond(), os.Getpid())
		if err := db.Snapshot(filepath.Join("backups", backupName)); err != nil {
			return nil, "", "", errors.New("не удалось сделать копию базы перед импортом, ничего не изменено")
		}
	}
	rep, err = importer.Run(db.DB, data, importOptions(r.apply, r.update))
	if err != nil {
		return nil, backupName, "", err
	}
	if r.apply {
		pruneImportBackups(importBackupsKeep, backupName)
		if !r.applyCores {
			if e := db.SyncMembership(); e != nil {
				warn = "Не удалось обновить доступ пользователей к подключениям: " + e.Error() + "."
			}
			return rep, backupName, warn, nil
		}
		inbounds, _ := db.GetInbounds()
		for _, ib := range inbounds {
			if e := core.EnsureForInbound(ib); e != nil {
				warn += " Ядро для «" + ib.Tag + "» не установлено: " + e.Error() + "."
			}
		}
		if e := applyCores(); e != nil {
			warn += " Ядра применить не удалось: " + e.Error() + "."
		}
		warn = strings.TrimSpace(warn)
	}
	return rep, backupName, warn, nil
}

// uploadedImport – загруженная база (одна временная копия) и поля формы.
type uploadedImport struct {
	path, cfgPath         string // cfgPath – config.json Xray (необязательно)
	source, mode, confirm string
	apiURL                string
	apiAuth               importer.APIAuth // только в памяти; стирается при уборке
	cleanup               func()
}

// saveUpload читает форму потоком: файл сразу пишется во временную папку (права 700, файл 600, лимит размера),
// в памяти и в служебных файлах формы он не оседает. Поля формы короткие.
func saveUpload(c *gin.Context) (*uploadedImport, error) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, importer.MaxFileSize+(1<<20))
	mr, err := c.Request.MultipartReader()
	if err != nil {
		return nil, errors.New("файл слишком большой или форма неверная")
	}
	root, err := importer.TempRoot()
	if err != nil {
		return nil, errors.New("не удалось подготовить папку для файла")
	}
	dir, err := os.MkdirTemp(root, "kitsune-upload-") // права 700, на диске в каталоге данных
	if err != nil {
		return nil, errors.New("не удалось сохранить файл")
	}
	up := &uploadedImport{}
	up.cleanup = func() { _ = os.RemoveAll(dir); up.apiAuth.Clear() }
	fail := func(msg string) (*uploadedImport, error) { up.cleanup(); return nil, errors.New(msg) }
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail("файл слишком большой или форма неверная")
		}
		switch name := part.FormName(); {
		case name == "file" && up.path == "":
			f, err := os.OpenFile(filepath.Join(dir, "src.db"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return fail("не удалось сохранить файл")
			}
			n, err := io.Copy(f, io.LimitReader(part, importer.MaxFileSize+1))
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil || n > importer.MaxFileSize {
				return fail("не удалось сохранить файл или он слишком большой")
			}
			up.path = f.Name()
		case name == "config" && up.cfgPath == "":
			f, err := os.OpenFile(filepath.Join(dir, "config.json"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return fail("не удалось сохранить файл")
			}
			n, err := io.Copy(f, io.LimitReader(part, importer.MaxConfigSize+1))
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil || n > importer.MaxConfigSize {
				return fail("не удалось сохранить файл настроек Xray или он слишком большой")
			}
			if n > 0 {
				up.cfgPath = f.Name()
			}
		case name == "url" || name == "token" || name == "username" || name == "password":
			v, _ := io.ReadAll(io.LimitReader(part, maxTokenField))
			switch name {
			case "url":
				up.apiURL = strings.TrimSpace(string(v))
			case "token":
				up.apiAuth.Token = strings.TrimSpace(string(v))
			case "username":
				up.apiAuth.Username = strings.TrimSpace(string(v))
			default:
				up.apiAuth.Password = string(v)
			}
		case name == "source" || name == "mode" || name == "confirm":
			v, _ := io.ReadAll(io.LimitReader(part, 64))
			switch name {
			case "source":
				up.source = string(v)
			case "mode":
				up.mode = string(v)
			default:
				up.confirm = string(v)
			}
		}
		_ = part.Close()
	}
	if up.path == "" && up.source != importer.SourceMarzbanAPI {
		return fail("выберите файл базы")
	}
	return up, nil
}

// maxTokenField – предел длины поля формы с адресом и данными доступа Marzban.
const maxTokenField = 4200

// importReadTimeout – сколько даётся на загрузку файла импорта.
const importReadTimeout = 15 * time.Minute

func handleImport(apply bool) gin.HandlerFunc {
	return handleImportSources(apply, false)
}

// The release enables only the Xray file source. Keep the other parsers
// testable while migration is being validated.
func handleImportSources(apply, allowMigration bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Занято до записи файла на диск: второй загрузке не нужно ни места, ни памяти.
		if !importMu.TryLock() {
			c.JSON(http.StatusConflict, gin.H{"error": "Импорт уже идёт, дождитесь его окончания"})
			return
		}
		defer importMu.Unlock()
		// Срок на чтение тела: замолкший клиент не должен держать импорт занятым до обрыва соединения.
		_ = http.NewResponseController(c.Writer).SetReadDeadline(time.Now().Add(importReadTimeout))
		up, err := saveUpload(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		defer up.cleanup()
		if !allowMigration && up.source != importer.SourceXray {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Поддерживается только config.json Xray"})
			return
		}
		if apply && up.confirm != "yes" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Импорт запускается только с подтверждением"})
			return
		}
		rep, backupName, warn, err := runImportLocked(importReq{source: up.source, path: up.path, cfgPath: up.cfgPath, apiURL: up.apiURL, apiAuth: up.apiAuth, apply: apply, update: up.mode == "update", upload: true, applyCores: true, ctx: c.Request.Context()})
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "backup": backupName})
			return
		}
		rep.Limit(importRows)
		out := gin.H{"report": rep}
		if apply {
			out["backup"] = backupName
			out["warning"] = warn
			out["message"] = "Импорт выполнен. Копия базы перед импортом: backups/" + backupName
		}
		c.JSON(http.StatusOK, out)
	}
}

// directCall: команда запущена как `kit import ...`, а не из меню; только тогда ошибка даёт код выхода 1.
var directCall bool

// resolveImportPath раскрывает ~ и относительный путь. Обёртка kit переходит в каталог установки и кладёт каталог,
// откуда её вызвали, в KIT_CWD; без неё (старая обёртка) относительный путь ищется там, где запущена команда.
func resolveImportPath(p string) (string, error) {
	switch {
	case p == "~" || strings.HasPrefix(p, "~/"):
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", errors.New("не удалось определить домашний каталог: укажите полный путь к файлу, например /root/x-ui.db")
		}
		p = filepath.Join(home, strings.TrimPrefix(p, "~"))
	case !filepath.IsAbs(p):
		if base := os.Getenv("KIT_CWD"); filepath.IsAbs(base) {
			p = filepath.Join(base, p)
		} else if _, err := os.Stat(p); err != nil {
			return "", errors.New("файл не найден: укажите полный путь от корня, например /root/x-ui.db")
		}
	}
	return filepath.Clean(p), nil
}

// readSecret спрашивает значение без вывода на экран (если ввод с терминала). Введённое нигде не сохраняется.
func readSecret(in *bufio.Reader, prompt string, hidden bool) string {
	fmt.Print(prompt)
	if st, err := os.Stdin.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 && hidden {
		stty := func(arg string) bool {
			c := exec.Command("stty", arg)
			c.Stdin = os.Stdin
			return c.Run() == nil
		}
		if stty("-echo") {
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, os.Interrupt)
			done := make(chan struct{})
			go func() {
				select {
				case <-sig:
					stty("echo")
					fmt.Println()
					os.Exit(130)
				case <-done:
				}
			}()
			defer func() { close(done); signal.Stop(sig); stty("echo"); fmt.Println() }()
		}
	}
	l, _ := in.ReadString('\n')
	return strings.TrimRight(l, "\r\n")
}

// askAPIAuth берёт доступ к API Marzban из переменных окружения (для скриптов) или спрашивает у пользователя.
// Из меню (fromMenu) значения из окружения используются только после явного согласия.
func askAPIAuth(in *bufio.Reader, fromMenu bool) importer.APIAuth {
	a := importer.APIAuth{Token: strings.TrimSpace(os.Getenv("KIT_MARZBAN_TOKEN")), Username: os.Getenv("KIT_MARZBAN_USER"), Password: os.Getenv("KIT_MARZBAN_PASSWORD")}
	for _, k := range []string{"KIT_MARZBAN_TOKEN", "KIT_MARZBAN_USER", "KIT_MARZBAN_PASSWORD"} {
		_ = os.Unsetenv(k)
	}
	if fromMenu && !a.Empty() {
		fmt.Print("Marzban access found in the environment. Use it? (y – yes, Enter – no, ask instead): ")
		l, _ := in.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(l)) != "y" {
			a.Clear()
		}
	}
	if !a.Empty() {
		return a
	}
	a.Token = strings.TrimSpace(readSecret(in, "Marzban admin token (Enter – log in with username and password instead): ", true))
	if a.Token == "" {
		a.Username = strings.TrimSpace(readSecret(in, "Marzban admin username: ", false))
		a.Password = readSecret(in, "Marzban admin password: ", true)
	}
	return a
}

// cmdImport imports a local Xray config. Without --apply it only previews.
func cmdImport(args []string) error {
	var apply, update bool
	var pos []string
	var cfg string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; a {
		case "--apply":
			apply = true
		case "--update":
			update = true
		case "--config":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "✗  --config needs a file path")
				if directCall {
					os.Exit(1)
				}
				return errors.New("--config needs a file path")
			}
			i++
			cfg = args[i]
		default:
			pos = append(pos, a)
		}
	}
	fail := func(err error) error {
		fmt.Fprintln(os.Stderr, "✗ ", err)
		if directCall {
			os.Exit(1)
		}
		return err
	}
	if len(pos) != 2 {
		fmt.Println("Usage: kit import xray FILE [--apply] [--update]")
		return nil
	}
	if pos[0] != importer.SourceXray || cfg != "" {
		return fail(errors.New("only Xray config.json is supported"))
	}
	path, err := resolveImportPath(pos[1])
	if err != nil {
		return fail(err)
	}
	db.InitDB()
	rep, backupName, warn, err := runImport(importReq{source: pos[0], path: path, apply: apply, update: update})
	if err != nil {
		return fail(err)
	}
	rep.Limit(importRows)
	printImportReport(rep)
	if !apply {
		fmt.Println("\nDry run: nothing was written. Add --apply to import.")
		return nil
	}
	fmt.Println("\nDone. Database copy before the import: backups/" + backupName)
	if warn != "" {
		fmt.Println("!  " + warn)
	}
	fmt.Println("The running panel and its Xray were not touched. To bring the imported connections up, run: kit restart")
	return nil
}

func printImportReport(r *importer.Report) {
	section := func(title string, items []importer.Item, s importer.Counts) {
		fmt.Printf("\n%s: create %d, update %d, exists %d, skipped %d, conflicts %d\n", title, s.Create, s.Update, s.Exists, s.Skip, s.Conflicts)
		for _, it := range items {
			line := fmt.Sprintf("  [%s] %s", it.Action, it.Name)
			if it.Details != "" {
				line += " – " + it.Details
			}
			if it.Reason != "" {
				line += " (" + it.Reason + ")"
			}
			fmt.Println(line)
		}
	}
	section("Users", r.Users, r.UserSum)
	if r.UsersMore > 0 {
		fmt.Printf("  ... and %d more users (totals above count everyone)\n", r.UsersMore)
	}
	section("Connections", r.Inbounds, r.InSum)
	if r.InboundsMore > 0 {
		fmt.Printf("  ... and %d more connections\n", r.InboundsMore)
	}
	for _, n := range r.Warnings {
		fmt.Println("\n!! ", n)
	}
	for _, n := range r.Notes {
		fmt.Println("\n! ", n)
	}
}
