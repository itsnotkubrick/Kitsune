// Package tgbot – админ-бот Telegram: статус сервера, пользователи, ссылка и QR, создание, продление, пауза.
// Работает через long polling (getUpdates): домен и входящие соединения не нужны. Отвечает только администраторам из списка и только в личной
// переписке: чужие сообщения и сообщения из групп молча игнорируются.
package tgbot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// User – пользователь панели глазами бота.
type User struct {
	ID       int
	Name     string
	Enabled  bool  // включён вручную
	Active   bool  // включён и не истёк срок, лимит не исчерпан
	Used     int64 // байт
	Limit    int64 // байт; 0 – без лимита
	ExpiryMs int64 // 0 – без срока
}

// Backend – то, что бот умеет делать в панели. Реализация лежит в cmd/server и вызывает те же функции, что и интерфейс панели.
type Backend interface {
	Status() string
	Users() []User
	Find(name string) (User, bool)
	ByID(id int) (User, bool)
	Create(name string, days, gb int) (User, error)
	Extend(id, days int) (User, error)
	SetEnabled(id int, on bool) (User, error)
	Delete(id int) error
	Link(id int) (string, error) // ссылка подписки
}

// Config – настройки бота; читаются заново на каждом шаге, поэтому изменения в панели действуют без перезапуска.
type Config struct {
	Token   string
	Admins  []int64
	Enabled bool
}

type Bot struct {
	Config  func() Config
	Backend Backend
	API     func() string // базовый адрес Bot API
	Audit   func(actor, action, detail string)
	Client  *http.Client

	offset   int64
	ready    bool
	lastTok  string
	warnedBy map[int64]bool
	kbSent   map[int64]bool   // администраторы, которым уже показаны кнопки внизу (один раз за запуск панели)
	pending  map[int64]string // что бот ждёт от администратора следующим сообщением (сейчас только «new»)
}

func (b *Bot) client() *http.Client {
	if b.Client != nil {
		return b.Client
	}
	return &http.Client{Timeout: 45 * time.Second}
}

// ---- Telegram ----

type tgUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}
type tgChat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}
type tgMessage struct {
	MessageID int     `json:"message_id"`
	From      *tgUser `json:"from"`
	Chat      tgChat  `json:"chat"`
	Text      string  `json:"text"`
}
type tgCallback struct {
	ID      string     `json:"id"`
	From    tgUser     `json:"from"`
	Message *tgMessage `json:"message"`
	Data    string     `json:"data"`
}
type update struct {
	UpdateID      int64       `json:"update_id"`
	Message       *tgMessage  `json:"message"`
	CallbackQuery *tgCallback `json:"callback_query"`
}

type button struct{ Text, Data string }

func keyboard(rows [][]button) map[string]any {
	var out [][]map[string]string
	for _, r := range rows {
		var row []map[string]string
		for _, b := range r {
			row = append(row, map[string]string{"text": b.Text, "callback_data": b.Data})
		}
		out = append(out, row)
	}
	return map[string]any{"inline_keyboard": out}
}

// call вызывает метод Bot API; токен в тексте ошибок не показывается.
func (b *Bot) call(ctx context.Context, token, method string, payload any, out any) (int, error) {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(b.API(), "/")+"/bot"+token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("не удалось связаться с Telegram")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client().Do(req)
	if err != nil {
		return 0, fmt.Errorf("не удалось связаться с Telegram")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if out != nil {
		_ = json.Unmarshal(raw, out)
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("Telegram ответил %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

func (b *Bot) send(ctx context.Context, cfg Config, chat int64, text string, kb [][]button) {
	if len(text) > 4000 {
		text = text[:3990] + "…"
	}
	p := map[string]any{"chat_id": chat, "text": text, "disable_web_page_preview": true}
	if len(kb) > 0 {
		p["reply_markup"] = keyboard(kb)
	}
	_, _ = b.call(ctx, cfg.Token, "sendMessage", p, nil)
}

// edit меняет сообщение с кнопками; если не вышло (сообщение старое или без изменений), присылает новое.
func (b *Bot) edit(ctx context.Context, cfg Config, chat int64, msgID int, text string, kb [][]button) {
	if len(text) > 4000 {
		text = text[:3990] + "…"
	}
	p := map[string]any{"chat_id": chat, "message_id": msgID, "text": text, "disable_web_page_preview": true}
	if len(kb) > 0 {
		p["reply_markup"] = keyboard(kb)
	}
	if _, err := b.call(ctx, cfg.Token, "editMessageText", p, nil); err != nil {
		b.send(ctx, cfg, chat, text, kb)
	}
}

func (b *Bot) sendPhoto(ctx context.Context, cfg Config, chat int64, png []byte, caption string) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("chat_id", strconv.FormatInt(chat, 10))
	_ = w.WriteField("caption", caption)
	fw, _ := w.CreateFormFile("photo", "qr.png")
	_, _ = fw.Write(png)
	_ = w.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(b.API(), "/")+"/bot"+cfg.Token+"/sendPhoto", &buf)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	if resp, err := b.client().Do(req); err == nil {
		resp.Body.Close()
	}
}

func (b *Bot) answerCallback(ctx context.Context, cfg Config, id, text string) {
	_, _ = b.call(ctx, cfg.Token, "answerCallbackQuery", map[string]any{"callback_query_id": id, "text": text}, nil)
}

// ---- Цикл ----

// Run крутит опрос Telegram, пока не отменён контекст. Выключенный бот, пустой токен или пустой список администраторов – ожидание.
func (b *Bot) Run(ctx context.Context) {
	wait := 5 * time.Second
	for ctx.Err() == nil {
		cfg := b.Config()
		if !cfg.Enabled || cfg.Token == "" || len(cfg.Admins) == 0 {
			b.ready = false
			sleep(ctx, 5*time.Second)
			continue
		}
		code, err := b.pollOnce(ctx, cfg)
		switch {
		case err == nil:
			wait = 2 * time.Second
		case code == http.StatusUnauthorized || code == http.StatusNotFound:
			log.Printf("Telegram-бот: токен не принят (ответ %d)", code)
			sleep(ctx, time.Minute)
		case code == http.StatusConflict:
			log.Printf("Telegram-бот: этот токен уже опрашивает другая программа (одновременно можно только одну)")
			sleep(ctx, 30*time.Second)
		default:
			sleep(ctx, wait)
			if wait < time.Minute {
				wait *= 2
			}
		}
	}
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// pollOnce забирает пачку сообщений и обрабатывает их. После запуска (или смены токена) старые сообщения пропускаются:
// команды, присланные пока панель была выключена, выполняться не должны.
func (b *Bot) pollOnce(ctx context.Context, cfg Config) (int, error) {
	if !b.ready || b.lastTok != cfg.Token {
		var res struct {
			Result []update `json:"result"`
		}
		if code, err := b.call(ctx, cfg.Token, "getUpdates", map[string]any{"offset": -1, "limit": 1, "timeout": 0}, &res); err != nil {
			return code, err
		}
		b.offset = 0
		if n := len(res.Result); n > 0 {
			b.offset = res.Result[n-1].UpdateID + 1
		}
		b.ready, b.lastTok = true, cfg.Token
		b.setCommands(ctx, cfg)
	}
	var res struct {
		Result []update `json:"result"`
	}
	code, err := b.call(ctx, cfg.Token, "getUpdates", map[string]any{
		"offset": b.offset, "timeout": 25, "allowed_updates": []string{"message", "callback_query"}}, &res)
	if err != nil {
		return code, err
	}
	for _, u := range res.Result {
		if u.UpdateID >= b.offset {
			b.offset = u.UpdateID + 1
		}
		b.handle(ctx, cfg, u)
	}
	return code, nil
}

// setCommands убирает меню команд («бургер» у поля ввода): вместо него постоянные кнопки под полем ввода. Набранные вручную команды работают.
func (b *Bot) setCommands(ctx context.Context, cfg Config) {
	for _, scope := range []map[string]string{{"type": "all_private_chats"}, {"type": "default"}} {
		_, _ = b.call(ctx, cfg.Token, "deleteMyCommands", map[string]any{"scope": scope}, nil)
	}
	// кнопка меню у поля ввода: стандартная (без списка команд её у бота с пустым списком команд нет)
	_, _ = b.call(ctx, cfg.Token, "setChatMenuButton", map[string]any{"menu_button": map[string]string{"type": "default"}}, nil)
}

func isAdmin(cfg Config, id int64) bool {
	for _, a := range cfg.Admins {
		if a == id {
			return true
		}
	}
	return false
}

func (b *Bot) audit(actor int64, action, detail string) {
	if b.Audit != nil {
		b.Audit("Telegram "+strconv.FormatInt(actor, 10), action, detail)
	}
}

// handle обрабатывает одно обновление. Посторонние и групповые чаты не получают даже отказа.
func (b *Bot) handle(ctx context.Context, cfg Config, u update) {
	switch {
	case u.Message != nil && u.Message.From != nil:
		m := u.Message
		if m.Chat.Type != "private" || !isAdmin(cfg, m.From.ID) {
			b.noteStranger(m.From.ID)
			return
		}
		if b.kbSent == nil {
			b.kbSent = map[int64]bool{}
		}
		if !b.kbSent[m.From.ID] {
			b.kbSent[m.From.ID] = true
			b.showKeyboard(ctx, cfg, m.Chat.ID, "Кнопки управления – под полем ввода.")
		}
		b.command(ctx, cfg, m.Chat.ID, m.From.ID, m.Text)
	case u.CallbackQuery != nil:
		cq := u.CallbackQuery
		if cq.Message == nil || cq.Message.Chat.Type != "private" || !isAdmin(cfg, cq.From.ID) {
			b.noteStranger(cq.From.ID)
			return
		}
		b.callback(ctx, cfg, cq)
	}
}

func (b *Bot) noteStranger(id int64) {
	if b.warnedBy == nil {
		b.warnedBy = map[int64]bool{}
	}
	if !b.warnedBy[id] && len(b.warnedBy) < 100 {
		b.warnedBy[id] = true
		log.Printf("Telegram-бот: сообщение от постороннего (ID %d) проигнорировано", id)
	}
}

// ---- Команды ----

const helpText = `Кнопки под полем ввода: Статус, Пользователи, Новый пользователь, Справка. Остальное – командами:
/status – состояние сервера
/users – список пользователей
/user имя – карточка (ссылка, продление, пауза)
/link имя – ссылка подписки
/qr имя – QR подписки
/new имя [дней] [ГБ] – создать пользователя
/extend имя дней – продлить срок
/pause имя, /resume имя – отключить и включить
/delete имя – удалить (с подтверждением)

Ссылки подписки видны только вам, в этой переписке.`

// Кнопки под полем ввода: постоянные, нажатие отправляет их текст как сообщение.
const (
	btnStatus = "📊 Статус"
	btnUsers  = "👥 Пользователи"
	btnNew    = "🆕 Новый пользователь"
	btnHelp   = "❓ Справка"
)

func replyKeyboard() map[string]any {
	return map[string]any{
		"keyboard":        [][]map[string]string{{{"text": btnStatus}, {"text": btnUsers}}, {{"text": btnNew}, {"text": btnHelp}}},
		"resize_keyboard": true,
		"is_persistent":   true,
	}
}

// showKeyboard показывает кнопки внизу; без звука.
func (b *Bot) showKeyboard(ctx context.Context, cfg Config, chat int64, text string) {
	_, _ = b.call(ctx, cfg.Token, "sendMessage", map[string]any{"chat_id": chat, "text": text, "reply_markup": replyKeyboard(), "disable_notification": true}, nil)
}

func mainMenu() [][]button {
	return [][]button{{{"Статус", "s"}, {"Пользователи", "m:0"}}}
}

func (b *Bot) command(ctx context.Context, cfg Config, chat, from int64, text string) {
	text = strings.TrimSpace(text)
	// нажатия кнопок внизу превращаются в команды
	switch text {
	case btnStatus:
		text = "/status"
	case btnUsers:
		text = "/users"
	case btnHelp:
		text = "/help"
	case btnNew:
		if b.pending == nil {
			b.pending = map[int64]string{}
		}
		b.pending[from] = "new"
		b.send(ctx, cfg, chat, "Напишите имя нового пользователя и, если нужно, число дней и лимит в ГБ через пробел. Например:\nalice 30 50\n(0 или пропуск – без ограничения). Отмена: /cancel", nil)
		return
	}
	// ожидаем имя нового пользователя: любое сообщение без «/» – его данные, команда отменяет ожидание
	if b.pending[from] == "new" {
		delete(b.pending, from)
		if !strings.HasPrefix(text, "/") && text != "" {
			text = "/new " + text
		}
	}
	if !strings.HasPrefix(text, "/") {
		b.send(ctx, cfg, chat, "Я понимаю кнопки внизу и команды. Нажмите «"+btnHelp+"».", nil)
		return
	}
	f := strings.Fields(text)
	cmd := strings.ToLower(strings.SplitN(strings.TrimPrefix(f[0], "/"), "@", 2)[0])
	args := f[1:]
	switch cmd {
	case "start", "help", "menu":
		b.showKeyboard(ctx, cfg, chat, helpText)
	case "cancel":
		b.send(ctx, cfg, chat, "Отменено.", nil)
	case "status":
		b.send(ctx, cfg, chat, b.Backend.Status(), nil)
	case "users":
		page := 0
		if len(args) > 0 {
			page, _ = strconv.Atoi(args[0])
		}
		t, kb := b.usersPage(page)
		b.send(ctx, cfg, chat, t, kb)
	case "user", "link", "qr", "extend", "pause", "resume", "delete":
		if len(args) == 0 {
			b.send(ctx, cfg, chat, "Укажите имя пользователя: /"+cmd+" имя", nil)
			return
		}
		u, ok := b.Backend.Find(args[0])
		if !ok {
			b.send(ctx, cfg, chat, "Пользователь «"+args[0]+"» не найден. Список: /users", nil)
			return
		}
		switch cmd {
		case "user":
			t, kb := cardText(u)
			b.send(ctx, cfg, chat, t, kb)
		case "link":
			b.sendLink(ctx, cfg, chat, u)
		case "qr":
			b.sendQR(ctx, cfg, chat, u)
		case "extend":
			days := 0
			if len(args) > 1 {
				days, _ = strconv.Atoi(args[1])
			}
			if days < 1 || days > 3650 {
				b.send(ctx, cfg, chat, "Укажите число дней от 1 до 3650: /extend "+u.Name+" 30", nil)
				return
			}
			b.doExtend(ctx, cfg, chat, 0, from, u, days)
		case "pause", "resume":
			b.doToggle(ctx, cfg, chat, 0, from, u, cmd == "resume")
		case "delete":
			t, kb := confirmDelete(u)
			b.send(ctx, cfg, chat, t, kb)
		}
	case "new":
		if len(args) == 0 {
			b.send(ctx, cfg, chat, "Формат: /new имя [дней] [ГБ]. Например: /new alice 30 50", nil)
			return
		}
		days, gb := 0, 0
		if len(args) > 1 {
			days, _ = strconv.Atoi(args[1])
		}
		if len(args) > 2 {
			gb, _ = strconv.Atoi(args[2])
		}
		if days < 0 || days > 3650 || gb < 0 || gb > 100000 {
			b.send(ctx, cfg, chat, "Дни: 0–3650, ГБ: 0–100000 (0 – без ограничения).", nil)
			return
		}
		u, err := b.Backend.Create(args[0], days, gb)
		if err != nil {
			b.send(ctx, cfg, chat, "Не удалось создать: "+err.Error(), nil)
			return
		}
		b.audit(from, "Создание пользователя", u.Name)
		t, kb := cardText(u)
		b.send(ctx, cfg, chat, "Пользователь создан.\n\n"+t, kb)
	default:
		b.send(ctx, cfg, chat, "Не знаю такой команды. Нажмите «"+btnHelp+"».", nil)
	}
}

func (b *Bot) callback(ctx context.Context, cfg Config, cq *tgCallback) {
	chat, msg := cq.Message.Chat.ID, cq.Message.MessageID
	parts := strings.Split(cq.Data, ":")
	id := func(i int) (User, bool) {
		if len(parts) <= i {
			return User{}, false
		}
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return User{}, false
		}
		return b.Backend.ByID(n)
	}
	switch parts[0] {
	case "s":
		b.answerCallback(ctx, cfg, cq.ID, "")
		b.send(ctx, cfg, chat, b.Backend.Status(), mainMenu())
	case "m":
		b.answerCallback(ctx, cfg, cq.ID, "")
		page := 0
		if len(parts) > 1 {
			page, _ = strconv.Atoi(parts[1])
		}
		t, kb := b.usersPage(page)
		b.edit(ctx, cfg, chat, msg, t, kb)
	case "u", "l", "q", "e", "t", "d", "dy":
		u, ok := id(1)
		if !ok {
			b.answerCallback(ctx, cfg, cq.ID, "Пользователь не найден")
			return
		}
		switch parts[0] {
		case "u":
			b.answerCallback(ctx, cfg, cq.ID, "")
			t, kb := cardText(u)
			b.edit(ctx, cfg, chat, msg, t, kb)
		case "l":
			b.answerCallback(ctx, cfg, cq.ID, "")
			b.sendLink(ctx, cfg, chat, u)
		case "q":
			b.answerCallback(ctx, cfg, cq.ID, "")
			b.sendQR(ctx, cfg, chat, u)
		case "e":
			days := 0
			if len(parts) > 2 {
				days, _ = strconv.Atoi(parts[2])
			}
			if days < 1 || days > 3650 {
				b.answerCallback(ctx, cfg, cq.ID, "Неверное число дней")
				return
			}
			b.answerCallback(ctx, cfg, cq.ID, "Продлеваю…")
			b.doExtend(ctx, cfg, chat, msg, cq.From.ID, u, days)
		case "t":
			b.answerCallback(ctx, cfg, cq.ID, "Меняю…")
			b.doToggle(ctx, cfg, chat, msg, cq.From.ID, u, !u.Enabled)
		case "d": // сначала только подтверждение: ничего не удаляется
			b.answerCallback(ctx, cfg, cq.ID, "")
			t, kb := confirmDelete(u)
			b.edit(ctx, cfg, chat, msg, t, kb)
		case "dy":
			if err := b.Backend.Delete(u.ID); err != nil {
				b.answerCallback(ctx, cfg, cq.ID, "Не удалось удалить")
				b.send(ctx, cfg, chat, "Не удалось удалить: "+err.Error(), nil)
				return
			}
			b.audit(cq.From.ID, "Удаление пользователя", u.Name)
			b.answerCallback(ctx, cfg, cq.ID, "Удалён")
			b.edit(ctx, cfg, chat, msg, "Пользователь "+u.Name+" удалён. Его ссылка подписки больше не работает.", [][]button{{{"‹ Список", "m:0"}}})
		}
	default:
		b.answerCallback(ctx, cfg, cq.ID, "")
	}
}

func (b *Bot) doExtend(ctx context.Context, cfg Config, chat int64, msg int, from int64, u User, days int) {
	nu, err := b.Backend.Extend(u.ID, days)
	if err != nil {
		b.send(ctx, cfg, chat, "Не удалось продлить: "+err.Error(), nil)
		return
	}
	b.audit(from, "Продление пользователя", fmt.Sprintf("%s +%d дн.", nu.Name, days))
	t, kb := cardText(nu)
	t = fmt.Sprintf("Срок продлён на %d дн.\n\n%s", days, t)
	if msg > 0 {
		b.edit(ctx, cfg, chat, msg, t, kb)
	} else {
		b.send(ctx, cfg, chat, t, kb)
	}
}

func (b *Bot) doToggle(ctx context.Context, cfg Config, chat int64, msg int, from int64, u User, on bool) {
	nu, err := b.Backend.SetEnabled(u.ID, on)
	if err != nil {
		b.send(ctx, cfg, chat, "Не удалось изменить: "+err.Error(), nil)
		return
	}
	act := "Пользователь отключён"
	if on {
		act = "Пользователь включён"
	}
	b.audit(from, act, nu.Name)
	t, kb := cardText(nu)
	if msg > 0 {
		b.edit(ctx, cfg, chat, msg, t, kb)
	} else {
		b.send(ctx, cfg, chat, t, kb)
	}
}

func (b *Bot) sendLink(ctx context.Context, cfg Config, chat int64, u User) {
	link, err := b.Backend.Link(u.ID)
	if err != nil {
		b.send(ctx, cfg, chat, err.Error(), nil)
		return
	}
	b.send(ctx, cfg, chat, "Ссылка подписки "+u.Name+":\n"+link+"\n\nНе публикуйте её: она даёт доступ к подключению.", nil)
}

func (b *Bot) sendQR(ctx context.Context, cfg Config, chat int64, u User) {
	link, err := b.Backend.Link(u.ID)
	if err != nil {
		b.send(ctx, cfg, chat, err.Error(), nil)
		return
	}
	png, err := qrcode.Encode(link, qrcode.Medium, 360)
	if err != nil {
		b.send(ctx, cfg, chat, "Не удалось нарисовать QR. Ссылка:\n"+link, nil)
		return
	}
	b.sendPhoto(ctx, cfg, chat, png, "QR подписки "+u.Name)
}

// ---- Тексты ----

const perPage = 8

func (b *Bot) usersPage(page int) (string, [][]button) {
	us := b.Backend.Users()
	if len(us) == 0 {
		return "Пользователей пока нет. Нажмите «" + btnNew + "» или /new имя [дней] [ГБ].", nil
	}
	pages := (len(us) + perPage - 1) / perPage
	if page < 0 {
		page = 0
	}
	if page >= pages {
		page = pages - 1
	}
	from, to := page*perPage, page*perPage+perPage
	if to > len(us) {
		to = len(us)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Пользователи (%d), страница %d из %d:\n", len(us), page+1, pages)
	var kb [][]button
	for _, u := range us[from:to] {
		sb.WriteString("\n" + icon(u) + " " + u.Name + " – " + traffic(u) + ", " + expiry(u))
		kb = append(kb, []button{{icon(u) + " " + u.Name, "u:" + strconv.Itoa(u.ID)}})
	}
	var nav []button
	if page > 0 {
		nav = append(nav, button{"‹ Назад", "m:" + strconv.Itoa(page-1)})
	}
	if page < pages-1 {
		nav = append(nav, button{"Дальше ›", "m:" + strconv.Itoa(page+1)})
	}
	if len(nav) > 0 {
		kb = append(kb, nav)
	}
	return sb.String(), kb
}

func cardText(u User) (string, [][]button) {
	id := strconv.Itoa(u.ID)
	state := "активен"
	switch {
	case !u.Enabled:
		state = "отключён вручную"
	case !u.Active:
		state = "не работает: исчерпан лимит или истёк срок"
	}
	t := fmt.Sprintf("%s %s\nСостояние: %s\nТрафик: %s\nСрок: %s", icon(u), u.Name, state, traffic(u), expiry(u))
	toggle := button{"Отключить", "t:" + id}
	if !u.Enabled {
		toggle = button{"Включить", "t:" + id}
	}
	return t, [][]button{
		{{"Ссылка", "l:" + id}, {"QR", "q:" + id}},
		{{"+7 дней", "e:" + id + ":7"}, {"+30 дней", "e:" + id + ":30"}},
		{toggle, {"Удалить…", "d:" + id}},
		{{"‹ Список", "m:0"}},
	}
}

// confirmDelete – запрос подтверждения: удаление необратимо, поэтому ни команда, ни кнопка «Удалить…» сами ничего не удаляют.
func confirmDelete(u User) (string, [][]button) {
	id := strconv.Itoa(u.ID)
	return "Удалить пользователя " + u.Name + "? Его ссылка подписки перестанет работать, это нельзя отменить.",
		[][]button{{{"Да, удалить", "dy:" + id}, {"Отмена", "u:" + id}}}
}

func icon(u User) string {
	switch {
	case !u.Enabled:
		return "⏸"
	case !u.Active:
		return "⛔"
	}
	return "✅"
}

func gb(n int64) string { return fmt.Sprintf("%.1f", float64(n)/(1<<30)) }

func traffic(u User) string {
	if u.Limit > 0 {
		return gb(u.Used) + " / " + gb(u.Limit) + " ГБ"
	}
	return gb(u.Used) + " ГБ, без лимита"
}

func expiry(u User) string {
	if u.ExpiryMs <= 0 {
		return "без срока"
	}
	t := time.UnixMilli(u.ExpiryMs)
	left := int(time.Until(t).Hours() / 24)
	if time.Now().After(t) {
		return "истёк " + t.Format("02.01.2006")
	}
	return fmt.Sprintf("до %s (%d дн.)", t.Format("02.01.2006"), left+1)
}
