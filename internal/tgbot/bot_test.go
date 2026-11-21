package tgbot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const tok = "123456:SECRET-TOKEN"

// fakeTG – поддельный Bot API: хранит очередь обновлений и записывает все вызовы.
type fakeTG struct {
	mu      sync.Mutex
	queue   []update
	calls   []call
	srv     *httptest.Server
	offsets []int64
}
type call struct {
	method string
	text   string
	chat   int64
	raw    map[string]any
	photo  []byte
}

func newFakeTG(t *testing.T) *fakeTG {
	f := &fakeTG{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/bot"+tok+"/") {
			http.Error(w, "bad token", 401)
			return
		}
		method := strings.TrimPrefix(r.URL.Path, "/bot"+tok+"/")
		c := call{method: method}
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
			if err := r.ParseMultipartForm(10 << 20); err == nil {
				if fl, _, err := r.FormFile("photo"); err == nil {
					c.photo, _ = io.ReadAll(fl)
				}
				c.text = r.FormValue("caption")
			}
		} else {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &c.raw)
			if s, ok := c.raw["text"].(string); ok {
				c.text = s
			}
			if n, ok := c.raw["chat_id"].(float64); ok {
				c.chat = int64(n)
			}
		}
		f.mu.Lock()
		f.calls = append(f.calls, c)
		var out any = map[string]any{"ok": true, "result": []any{}}
		if method == "getUpdates" {
			off, _ := c.raw["offset"].(float64)
			f.offsets = append(f.offsets, int64(off))
			var res []update
			if off < 0 { // «последнее обновление»
				if n := len(f.queue); n > 0 {
					res = f.queue[n-1:]
				}
			} else {
				for _, u := range f.queue {
					if u.UpdateID >= int64(off) {
						res = append(res, u)
					}
				}
			}
			out = map[string]any{"ok": true, "result": res}
		}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTG) sent() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []call
	for _, c := range f.calls {
		if c.method == "sendMessage" || c.method == "editMessageText" || c.method == "sendPhoto" {
			out = append(out, c)
		}
	}
	return out
}

type fakeBackend struct {
	users []User
	next  int
}

func (b *fakeBackend) Status() string { return "Kitsune: всё работает" }
func (b *fakeBackend) Users() []User  { return append([]User(nil), b.users...) }
func (b *fakeBackend) find(f func(User) bool) (User, bool) {
	for _, u := range b.users {
		if f(u) {
			return u, true
		}
	}
	return User{}, false
}
func (b *fakeBackend) Find(name string) (User, bool) {
	return b.find(func(u User) bool { return strings.EqualFold(u.Name, name) })
}
func (b *fakeBackend) ByID(id int) (User, bool) {
	return b.find(func(u User) bool { return u.ID == id })
}
func (b *fakeBackend) Create(name string, days, gb int) (User, error) {
	if _, ok := b.Find(name); ok {
		return User{}, errors.New("такой пользователь уже есть")
	}
	b.next++
	u := User{ID: 100 + b.next, Name: name, Enabled: true, Active: true, Limit: int64(gb) << 30}
	if days > 0 {
		u.ExpiryMs = time.Now().Add(time.Duration(days) * 24 * time.Hour).UnixMilli()
	}
	b.users = append(b.users, u)
	return u, nil
}
func (b *fakeBackend) mutate(id int, f func(*User)) (User, error) {
	for i := range b.users {
		if b.users[i].ID == id {
			f(&b.users[i])
			return b.users[i], nil
		}
	}
	return User{}, errors.New("нет такого")
}
func (b *fakeBackend) Extend(id, days int) (User, error) {
	return b.mutate(id, func(u *User) { u.ExpiryMs = time.Now().Add(time.Duration(days) * 24 * time.Hour).UnixMilli() })
}
func (b *fakeBackend) SetEnabled(id int, on bool) (User, error) {
	return b.mutate(id, func(u *User) { u.Enabled, u.Active = on, on })
}
func (b *fakeBackend) Delete(id int) error {
	for i, u := range b.users {
		if u.ID == id {
			b.users = append(b.users[:i], b.users[i+1:]...)
			return nil
		}
	}
	return errors.New("нет такого")
}
func (b *fakeBackend) Link(id int) (string, error) {
	return fmt.Sprintf("https://panel.example/sub/abc%d", id), nil
}

func newBot(t *testing.T) (*Bot, *fakeTG, *fakeBackend, *[]string) {
	f := newFakeTG(t)
	be := &fakeBackend{users: []User{{ID: 1, Name: "alice", Enabled: true, Active: true, Used: 3 << 30, Limit: 10 << 30}}}
	var audit []string
	b := &Bot{
		Config:  func() Config { return Config{Token: tok, Admins: []int64{7}, Enabled: true} },
		Backend: be,
		API:     func() string { return f.srv.URL },
		Audit:   func(actor, action, detail string) { audit = append(audit, actor+"|"+action+"|"+detail) },
	}
	return b, f, be, &audit
}

func msg(from int64, chatType, text string) update {
	return update{UpdateID: 1, Message: &tgMessage{MessageID: 5, From: &tgUser{ID: from}, Chat: tgChat{ID: from, Type: chatType}, Text: text}}
}

func (b *Bot) feed(u update) { b.handle(context.Background(), b.Config(), u) }

func TestStrangersAndGroupsGetNothing(t *testing.T) {
	b, f, _, _ := newBot(t)
	b.feed(msg(99, "private", "/users")) // не администратор
	b.feed(msg(99, "private", "/new hacker 365"))
	b.feed(msg(7, "group", "/users")) // администратор, но в группе
	b.feed(msg(7, "supergroup", "/link alice"))
	b.feed(update{UpdateID: 2, CallbackQuery: &tgCallback{ID: "c", From: tgUser{ID: 99}, Message: &tgMessage{Chat: tgChat{ID: 99, Type: "private"}}, Data: "t:1"}})
	b.feed(update{UpdateID: 3, CallbackQuery: &tgCallback{ID: "c", From: tgUser{ID: 7}, Message: &tgMessage{Chat: tgChat{ID: -100, Type: "group"}}, Data: "l:1"}})
	if len(f.calls) != 0 {
		t.Fatalf("ни ответов, ни отказов быть не должно: %+v", f.calls)
	}
	if _, ok := b.Backend.Find("hacker"); ok {
		t.Fatal("посторонний создал пользователя")
	}
}

func TestAdminCommands(t *testing.T) {
	b, f, be, audit := newBot(t)
	for _, c := range []string{"/start", "/status", "/users", "/user alice", "/link alice", "/qr alice", "/new bob 30 50", "/extend alice 7", "/pause alice", "/resume alice", "/unknown", "/user nobody", "/extend alice abc", "/new bob"} {
		b.feed(msg(7, "private", c))
	}
	sent := f.sent()
	has := func(sub string) bool {
		for _, c := range sent {
			if strings.Contains(c.text, sub) {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"Кнопки под полем ввода", "всё работает", "Пользователи (1)", "alice", "https://panel.example/sub/abc1", "Пользователь создан", "Срок продлён на 7 дн.", "не найден", "Не знаю такой команды", "Укажите число дней", "уже есть"} {
		if !has(want) {
			t.Errorf("нет ответа с %q\n%v", want, texts(sent))
		}
	}
	var photo bool
	for _, c := range sent {
		if c.method == "sendPhoto" && len(c.photo) > 8 && string(c.photo[1:4]) == "PNG" {
			photo = true
		}
	}
	if !photo {
		t.Error("QR не отправлен как PNG")
	}
	bob, ok := be.Find("bob")
	if !ok || bob.Limit != 50<<30 || bob.ExpiryMs == 0 {
		t.Errorf("bob: %+v", bob)
	}
	if a, _ := be.Find("alice"); !a.Enabled {
		t.Error("после /pause и /resume alice должна быть включена")
	}
	joined := strings.Join(*audit, "\n")
	for _, w := range []string{"Telegram 7|Создание пользователя|bob", "Продление пользователя|alice +7 дн.", "Пользователь отключён|alice", "Пользователь включён|alice"} {
		if !strings.Contains(joined, w) {
			t.Errorf("в журнале нет %q:\n%s", w, joined)
		}
	}
}

func texts(cs []call) []string {
	var out []string
	for _, c := range cs {
		out = append(out, strings.ReplaceAll(c.text, "\n", " | "))
	}
	return out
}

func TestCallbacksEditCardsAndActions(t *testing.T) {
	b, f, be, _ := newBot(t)
	cb := func(data string) update {
		return update{UpdateID: 1, CallbackQuery: &tgCallback{ID: "q1", From: tgUser{ID: 7}, Message: &tgMessage{MessageID: 9, Chat: tgChat{ID: 7, Type: "private"}}, Data: data}}
	}
	b.feed(cb("u:1"))
	b.feed(cb("t:1")) // отключить
	if u, _ := be.ByID(1); u.Enabled {
		t.Fatal("кнопка «Отключить» не сработала")
	}
	b.feed(cb("t:1")) // включить
	b.feed(cb("e:1:30"))
	b.feed(cb("l:1"))
	b.feed(cb("q:1"))
	b.feed(cb("m:0"))
	b.feed(cb("e:1:99999")) // неверное число дней
	b.feed(cb("u:424242"))  // нет такого
	if u, _ := be.ByID(1); !u.Enabled || u.ExpiryMs == 0 {
		t.Errorf("после включения и продления: %+v", u)
	}
	var edits, answers int
	for _, c := range f.calls {
		switch c.method {
		case "editMessageText":
			edits++
		case "answerCallbackQuery":
			answers++
		}
	}
	if edits < 4 || answers < 7 {
		t.Errorf("правок карточки %d, ответов на нажатия %d: %v", edits, answers, texts(f.sent()))
	}
	// на нажатие кнопки всегда отвечаем: иначе в Telegram крутятся часики
	if answers != 9 {
		t.Errorf("каждое нажатие должно получить ответ, ответов %d", answers)
	}
}

func TestBacklogIsSkippedAfterStart(t *testing.T) {
	b, f, be, _ := newBot(t)
	old := msg(7, "private", "/new oldcmd 1")
	old.UpdateID = 10
	f.queue = []update{old}
	if _, err := b.pollOnce(context.Background(), b.Config()); err != nil {
		t.Fatal(err)
	}
	if _, ok := be.Find("oldcmd"); ok {
		t.Fatal("старое сообщение, пришедшее пока бот был выключен, выполнено")
	}
	fresh := msg(7, "private", "/new fresh 1")
	fresh.UpdateID = 11
	f.mu.Lock()
	f.queue = append(f.queue, fresh)
	f.mu.Unlock()
	if _, err := b.pollOnce(context.Background(), b.Config()); err != nil {
		t.Fatal(err)
	}
	if _, ok := be.Find("fresh"); !ok {
		t.Fatal("новое сообщение не обработано")
	}
	// первый запрос «-1» узнаёт последнее старое обновление, затем опрос идёт с 11; после обработки обновления 11 смещение становится 12
	if len(f.offsets) < 3 || f.offsets[0] != -1 || f.offsets[1] != 11 || f.offsets[2] != 11 || b.offset != 12 {
		t.Errorf("смещения getUpdates: %v, итоговое %d (ждали -1, 11, 11 и 12)", f.offsets, b.offset)
	}
}

func TestRunWaitsWhenDisabledAndStops(t *testing.T) {
	b, f, _, _ := newBot(t)
	b.Config = func() Config { return Config{Token: tok, Admins: nil, Enabled: true} } // нет администраторов: бот молчит
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { b.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run не остановился по отмене контекста")
	}
	if len(f.calls) != 0 {
		t.Errorf("без администраторов бот не должен обращаться к Telegram: %v", f.calls)
	}
}

func TestTokenNeverInErrors(t *testing.T) {
	b, _, _, _ := newBot(t)
	b.API = func() string { return "http://127.0.0.1:1" } // порт закрыт
	_, err := b.call(context.Background(), tok, "getMe", nil, nil)
	if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), tok) {
		t.Fatalf("токен попал в текст ошибки: %v", err)
	}
}

func TestPaging(t *testing.T) {
	b, _, be, _ := newBot(t)
	for i := 0; i < 20; i++ {
		be.users = append(be.users, User{ID: 10 + i, Name: fmt.Sprintf("u%02d", i), Enabled: true, Active: true})
	}
	t1, kb := b.usersPage(0)
	if !strings.Contains(t1, "страница 1 из 3") || len(kb) != perPage+1 || kb[len(kb)-1][0].Data != "m:1" {
		t.Errorf("первая страница: %q %v", t1, kb[len(kb)-1])
	}
	_, kb = b.usersPage(99) // за пределами – последняя
	if kb[len(kb)-1][0].Data != "m:1" {
		t.Errorf("последняя страница должна вести назад: %v", kb[len(kb)-1])
	}
}

func keyboardCalls(f *fakeTG) (shown int, last map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if rm, ok := c.raw["reply_markup"].(map[string]any); ok {
			if _, isReply := rm["keyboard"]; isReply {
				shown++
				last = rm
			}
		}
	}
	return
}

func TestBottomButtonsShownOnceAndWork(t *testing.T) {
	b, f, _, _ := newBot(t)
	b.feed(msg(7, "private", btnUsers))
	shown, kb := keyboardCalls(f)
	if shown != 1 {
		t.Fatalf("кнопки внизу должны появиться при первом сообщении: %d", shown)
	}
	if kb["resize_keyboard"] != true || kb["is_persistent"] != true {
		t.Errorf("кнопки должны быть постоянными и компактными: %v", kb)
	}
	var labels []string
	for _, row := range kb["keyboard"].([]any) {
		for _, bt := range row.([]any) {
			labels = append(labels, bt.(map[string]any)["text"].(string))
		}
	}
	if strings.Join(labels, "|") != strings.Join([]string{btnStatus, btnUsers, btnNew, btnHelp}, "|") {
		t.Errorf("кнопки: %v", labels)
	}
	b.feed(msg(7, "private", btnStatus))
	b.feed(msg(7, "private", btnHelp))
	if shown2, _ := keyboardCalls(f); shown2 != 2 { // повторно кнопки показывает только «Справка» (она же отвечает с кнопками)
		t.Errorf("кнопки показываются при первом сообщении и в «Справке», всего %d", shown2)
	}
	sent := texts(f.sent())
	joined := strings.Join(sent, "\n")
	for _, want := range []string{"Пользователи (1)", "всё работает", "Кнопки под полем ввода"} {
		if !strings.Contains(joined, want) {
			t.Errorf("нет ответа %q: %v", want, sent)
		}
	}
}

func TestNewUserViaButtonFlow(t *testing.T) {
	b, f, be, _ := newBot(t)
	b.feed(msg(7, "private", btnNew))
	if !strings.Contains(strings.Join(texts(f.sent()), "\n"), "Напишите имя нового пользователя") {
		t.Fatalf("бот не спросил данные: %v", texts(f.sent()))
	}
	b.feed(msg(7, "private", "carol 10 2"))
	c, ok := be.Find("carol")
	if !ok || c.Limit != 2<<30 || c.ExpiryMs == 0 {
		t.Fatalf("пользователь не создан по ответу: %+v %v", c, ok)
	}
	// после создания бот больше ничего не ждёт
	b.feed(msg(7, "private", "просто текст"))
	if _, ok := be.Find("просто"); ok {
		t.Error("обычный текст создал пользователя")
	}
	// команда после нажатия «Новый пользователь» отменяет ожидание и не становится именем
	b.feed(msg(7, "private", btnNew))
	b.feed(msg(7, "private", "/users"))
	b.feed(msg(7, "private", "dave"))
	if _, ok := be.Find("dave"); ok {
		t.Error("ожидание имени пережило команду")
	}
	for _, name := range []string{"/users", "users"} {
		if _, ok := be.Find(name); ok {
			t.Errorf("команда стала именем пользователя: %q", name)
		}
	}
	// ожидание привязано к администратору: ответ чужого человека ничего не создаёт
	b.feed(msg(7, "private", btnNew))
	b.feed(msg(99, "private", "mallory"))
	if _, ok := be.Find("mallory"); ok {
		t.Error("посторонний создал пользователя через чужое ожидание")
	}
	b.feed(msg(7, "private", btnNew))
	b.feed(msg(7, "private", "/cancel"))
	b.feed(msg(7, "private", "erin"))
	if _, ok := be.Find("erin"); ok {
		t.Error("/cancel не отменил ожидание")
	}
}

func TestCommandMenuIsRemoved(t *testing.T) {
	b, f, _, _ := newBot(t)
	if _, err := b.pollOnce(context.Background(), b.Config()); err != nil {
		t.Fatal(err)
	}
	var del, set int
	f.mu.Lock()
	for _, c := range f.calls {
		switch c.method {
		case "deleteMyCommands":
			del++
		case "setMyCommands":
			set++
		}
	}
	f.mu.Unlock()
	if del != 2 || set != 0 {
		t.Errorf("меню команд («бургер») должно удаляться: deleteMyCommands=%d setMyCommands=%d", del, set)
	}
}

func TestDeleteAlwaysAsksForConfirmation(t *testing.T) {
	b, f, be, audit := newBot(t)
	cb := func(from int64, data string) update {
		return update{UpdateID: 1, CallbackQuery: &tgCallback{ID: "q", From: tgUser{ID: from}, Message: &tgMessage{MessageID: 9, Chat: tgChat{ID: from, Type: "private"}}, Data: data}}
	}
	// команда только просит подтверждение
	b.feed(msg(7, "private", "/delete alice"))
	if _, ok := be.Find("alice"); !ok {
		t.Fatal("команда /delete удалила пользователя без подтверждения")
	}
	if !strings.Contains(strings.Join(texts(f.sent()), "\n"), "Удалить пользователя alice?") {
		t.Fatalf("нет запроса подтверждения: %v", texts(f.sent()))
	}
	// кнопка «Удалить…» тоже только спрашивает
	b.feed(cb(7, "d:1"))
	if _, ok := be.Find("alice"); !ok {
		t.Fatal("кнопка «Удалить…» удалила пользователя без подтверждения")
	}
	// «Отмена» возвращает карточку
	b.feed(cb(7, "u:1"))
	if _, ok := be.Find("alice"); !ok {
		t.Fatal("отмена удалила пользователя")
	}
	// чужое подтверждение ничего не делает
	b.feed(cb(99, "dy:1"))
	if _, ok := be.Find("alice"); !ok {
		t.Fatal("посторонний удалил пользователя")
	}
	// подтверждение администратора удаляет и пишет в журнал
	b.feed(cb(7, "dy:1"))
	if _, ok := be.Find("alice"); ok {
		t.Fatal("подтверждённое удаление не сработало")
	}
	if !strings.Contains(strings.Join(*audit, "\n"), "Telegram 7|Удаление пользователя|alice") {
		t.Errorf("в журнале нет удаления: %v", *audit)
	}
	// повторное подтверждение уже удалённого – понятный ответ, без падения
	b.feed(cb(7, "dy:1"))
	b.feed(msg(7, "private", "/delete nobody"))
}
