package main

import (
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"kitsune/internal/db"
	"kitsune/internal/events"
	"kitsune/internal/totp"
)

// Защита от подбора пароля: после 8 неудачных попыток вход с адреса закрывается на 10 минут.
// Проверки с одного адреса идут по одной (loginEnter занимает слот на время проверки пароля и кода):
// параллельный перебор не проскочит лимит, пока идёт медленный bcrypt, а верные параллельные
// запросы не получают отказ – они ждут своей очереди. Считаются только завершённые неудачи.
// Успешный вход сбрасывает счётчик.
var (
	loginMu    sync.Mutex
	loginCond  = sync.NewCond(&loginMu)
	loginFails = map[string][]time.Time{}
	loginBusy  = map[string]*loginQueue{}
)

// loginQueue – состояние очереди одного адреса: занят ли слот и сколько запросов ждёт.
type loginQueue struct {
	held    bool
	waiters int
}

// loginTableMax – потолок числа адресов в таблице неудач.
const loginTableMax = 4096

const (
	loginMaxFails = 8
	loginWindow   = 10 * time.Minute
	// loginMaxWaiters – сколько запросов с одного адреса ждут слот; остальным сразу 429.
	loginMaxWaiters = 32
)

// Итоги loginEnter.
const (
	loginAllowed  = iota // слот занят, можно проверять
	loginBlocked         // адрес закрыт: 8 неудач за окно
	loginOverflow        // слишком много одновременных запросов с адреса
)

// loginKey – ключ лимита: IPv4 как есть, IPv6 по сети /64 (одному клиенту отдают целую /64).
func loginKey(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ip
	}
	if p4 := p.To4(); p4 != nil {
		return p4.String()
	}
	return p.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

func recentFails(key string) []time.Time {
	cutoff := time.Now().Add(-loginWindow)
	list := loginFails[key][:0]
	for _, t := range loginFails[key] {
		if t.After(cutoff) {
			list = append(list, t)
		}
	}
	if len(list) == 0 {
		delete(loginFails, key)
	} else {
		loginFails[key] = list
	}
	return list
}

// loginSlot – занятый слот проверки. Итог задают fail / success, освобождает done (можно через defer,
// повторный вызов безвреден). Без fail и success слот просто освобождается, попытка не засчитывается.
type loginSlot struct {
	key      string
	outcome  int // 0 – ничего, 1 – неудача, 2 – успех
	finished bool
}

// loginEnter ждёт свою очередь для адреса и занимает слот. Закрытый адрес проверяется уже после
// ожидания, под замком: поэтому неудач будет не больше loginMaxFails.
func loginEnter(ip string) (*loginSlot, int) {
	key := loginKey(ip)
	loginMu.Lock()
	defer loginMu.Unlock()
	q := loginBusy[key]
	if q == nil {
		q = &loginQueue{}
		loginBusy[key] = q
	}
	if q.held {
		if q.waiters >= loginMaxWaiters {
			return nil, loginOverflow
		}
		q.waiters++
		for q.held {
			loginCond.Wait()
		}
		q.waiters--
	}
	if len(recentFails(key)) >= loginMaxFails {
		loginDropQueue(key, q)
		return nil, loginBlocked
	}
	q.held = true
	return &loginSlot{key: key}, loginAllowed
}

// loginDropQueue убирает пустую очередь (вызывать под замком).
func loginDropQueue(key string, q *loginQueue) {
	if !q.held && q.waiters == 0 {
		delete(loginBusy, key)
	}
}

func (s *loginSlot) fail()    { s.outcome = 1 }
func (s *loginSlot) success() { s.outcome = 2 }

// done применяет итог и освобождает слот.
func (s *loginSlot) done() {
	if s == nil || s.finished {
		return
	}
	s.finished = true
	loginMu.Lock()
	defer loginMu.Unlock()
	switch s.outcome {
	case 1:
		if _, known := loginFails[s.key]; !known && len(loginFails) >= loginTableMax {
			pruneLoginFails()
		}
		loginFails[s.key] = append(loginFails[s.key], time.Now())
	case 2:
		delete(loginFails, s.key)
	}
	if q := loginBusy[s.key]; q != nil {
		q.held = false
		loginDropQueue(s.key, q)
	}
	loginCond.Broadcast()
}

// pruneLoginFails освобождает место до 3/4 потолка: убирает устаревшее, потом один раз сортирует
// и вытесняет сначала незакрытые адреса (самые давние), закрытые – только в крайнем случае.
func pruneLoginFails() {
	type entry struct {
		key     string
		last    time.Time
		blocked bool
	}
	items := make([]entry, 0, len(loginFails))
	for k := range loginFails {
		l := recentFails(k)
		if len(l) > 0 {
			items = append(items, entry{k, l[len(l)-1], len(l) >= loginMaxFails})
		}
	}
	drop := len(loginFails) - loginTableMax*3/4 + 1
	if drop <= 0 {
		return
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].blocked != items[j].blocked {
			return !items[i].blocked
		}
		return items[i].last.Before(items[j].last)
	})
	for i := 0; i < drop && i < len(items); i++ {
		delete(loginFails, items[i].key)
	}
}

// Лимит неверных кодов 2FA на учётную запись (а не на адрес): перебор кода с разных адресов
// упирается в тот же счётчик. Код проверяется только после верного пароля, так что закрыть
// вход админу таким способом может лишь тот, кто знает пароль.
var (
	totpMu    sync.Mutex
	totpFails []time.Time
)

// totpCheck под одним замком проверяет лимит, код и повторное использование шага, и сразу
// запоминает шаг: два параллельных запроса с одним верным кодом не пройдут оба.
// limited=true – лимит исчерпан, код не проверялся.
func totpCheck(code string) (ok, limited bool) {
	totpMu.Lock()
	defer totpMu.Unlock()
	cutoff := time.Now().Add(-loginWindow)
	kept := totpFails[:0]
	for _, t := range totpFails {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	totpFails = kept
	if len(totpFails) >= loginMaxFails {
		return false, true
	}
	step, valid := totp.Verify(db.GetSetting("totp_secret", ""), code, time.Now())
	last, _ := strconv.ParseUint(db.GetSetting("totp_last_step", "0"), 10, 64)
	if !valid || step <= last { // неверный или уже использованный код
		totpFails = append(totpFails, time.Now())
		return false, false
	}
	_ = db.SetSetting("totp_last_step", strconv.FormatUint(step, 10))
	totpFails = nil
	return true, false
}

// totpLimitedNotice пишет в аудит и уведомления об исчерпанном лимите кодов 2FA, один раз на окно.
func totpLimitedNotice(user, ip string) {
	if !loginNoticeDue("totp-codes") {
		return
	}
	events.Audit(user, "Лимит неверных кодов двухфакторного входа исчерпан: коды закрыты на 10 минут", ip)
	events.Notify("totp", "codes", "много неверных кодов двухфакторного входа: коды закрыты на 10 минут", 30*time.Minute)
}

// Уведомление о блокировке пишется один раз на блокировку, а не на каждый запрос.
var loginNoticed = map[string]time.Time{}

func loginNoticeDue(ip string) bool {
	key := loginKey(ip)
	loginMu.Lock()
	defer loginMu.Unlock()
	if len(loginNoticed) >= loginTableMax {
		loginNoticed = map[string]time.Time{}
	}
	if t, ok := loginNoticed[key]; ok && time.Since(t) < loginWindow {
		return false
	}
	loginNoticed[key] = time.Now()
	return true
}
