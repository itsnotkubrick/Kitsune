package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
	"kitsune/internal/events"
	"kitsune/internal/totp"
)

// failLogin проходит один неудачный вход с адреса; false – адрес закрыт.
func failLogin(ip string) bool {
	slot, v := loginEnter(ip)
	if v != loginAllowed {
		return false
	}
	slot.fail()
	slot.done()
	return true
}

func resetLoginFails() {
	loginMu.Lock()
	loginFails = map[string][]time.Time{}
	loginMu.Unlock()
	resetTOTPFails()
}

// Подмена X-Forwarded-For не должна менять ключ лимита: адрес берётся из TCP-соединения.
func TestClientIPIgnoresForwardedHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if err := r.SetTrustedProxies(trustedProxiesFromEnv()); err != nil {
		t.Fatal(err)
	}
	var got []string
	r.GET("/", func(c *gin.Context) { got = append(got, c.ClientIP()) })
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "203.0.113.9:4000"
		req.Header.Set("X-Forwarded-For", "198.51.100."+strconv.Itoa(i))
		req.Header.Set("X-Real-IP", "198.51.100.77")
		r.ServeHTTP(httptest.NewRecorder(), req)
	}
	for _, ip := range got {
		if ip != "203.0.113.9" {
			t.Fatalf("ClientIP = %q, ждали 203.0.113.9", ip)
		}
	}
}

func TestLoginLimitNotBypassedByXFF(t *testing.T) {
	resetLoginFails()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	_ = r.SetTrustedProxies(trustedProxiesFromEnv())
	r.GET("/", func(c *gin.Context) {
		ip := c.ClientIP()
		if !failLogin(ip) {
			c.Status(http.StatusTooManyRequests)
			return
		}
		c.Status(http.StatusUnauthorized)
	})
	last := 0
	for i := 0; i < loginMaxFails+3; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "203.0.113.9:4000"
		req.Header.Set("X-Forwarded-For", "10.1.1."+strconv.Itoa(i))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		last = w.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("после %d попыток с разным XFF ждали 429, получили %d", loginMaxFails+3, last)
	}
}

func TestParseTrustedProxies(t *testing.T) {
	if got := parseTrustedProxies(""); len(got) != 0 {
		t.Fatalf("по умолчанию должно быть пусто: %v", got)
	}
	got := parseTrustedProxies("127.0.0.1, ::1, 10.0.0.0/8, мусор, 0.0.0.0/0, ::/0, 1.2.3.4/0, 0::/0, 0.0.0.0/1, 128.0.0.0/1, ::ffff:0.0.0.0/96, ::/8, 0.0.0.0/7, 2001:db8::/32")
	want := []string{"127.0.0.1", "::1", "10.0.0.0/8", "2001:db8::/32"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestLoginTableCapped(t *testing.T) {
	resetLoginFails()
	for i := 0; i < loginTableMax*2; i++ {
		failLogin("ip-" + strconv.Itoa(i))
	}
	loginMu.Lock()
	n := len(loginFails)
	_, newest := loginFails["ip-"+strconv.Itoa(loginTableMax*2-1)]
	_, oldest := loginFails["ip-0"]
	loginMu.Unlock()
	if n > loginTableMax {
		t.Fatalf("таблица выросла до %d, потолок %d", n, loginTableMax)
	}
	if !newest || oldest {
		t.Fatalf("вытеснение неверное: newest=%v oldest=%v", newest, oldest)
	}
}

func TestLoginBlockStillWorks(t *testing.T) {
	resetLoginFails()
	for i := 0; i < loginMaxFails; i++ {
		failLogin("attacker")
	}
	if failLogin("attacker") {
		t.Fatal("адрес должен быть закрыт")
	}
}

func disableTOTP(t *testing.T, password, code string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	_ = r.SetTrustedProxies(nil)
	r.POST("/d", handleTOTPDisable)
	body := `{"password":"` + password + `","code":"` + code + `"}`
	req := httptest.NewRequest("POST", "/d", strings.NewReader(body))
	req.RemoteAddr = "203.0.113.9:4000"
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestTOTPDisableChecksReplayAndLimit(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	resetLoginFails()
	user := db.GetSetting("admin_username", "admin")
	if err := db.UpdateAdminCredentials(user, "pw-for-test"); err != nil {
		t.Fatal(err)
	}
	secret, err := totp.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code, _ := totp.Code(secret, now)
	_ = db.SetSetting("totp_enabled", "1")
	_ = db.SetSetting("totp_secret", secret)

	// уже использованный код (повтор) не принимается
	_ = db.SetSetting("totp_last_step", strconv.FormatUint(totp.Step(now)+1, 10))
	if w := disableTOTP(t, "pw-for-test", code); w.Code != http.StatusForbidden {
		t.Fatalf("повтор кода: %d", w.Code)
	}
	if db.GetSetting("totp_enabled", "") != "1" {
		t.Fatal("2FA выключилась по использованному коду")
	}

	// перебор упирается в лимит
	for i := 0; i < loginMaxFails; i++ {
		disableTOTP(t, "pw-for-test", "000000")
	}
	if w := disableTOTP(t, "pw-for-test", code); w.Code != http.StatusTooManyRequests {
		t.Fatalf("ждали 429, получили %d", w.Code)
	}

	// свежий код при чистом счётчике выключает
	resetLoginFails()
	_ = db.SetSetting("totp_last_step", "0")
	if w := disableTOTP(t, "pw-for-test", code); w.Code != http.StatusOK {
		t.Fatalf("верный код: %d %s", w.Code, w.Body.String())
	}
	if db.GetSetting("totp_enabled", "") == "1" {
		t.Fatal("2FA не выключилась")
	}
}

func TestParseTrustedProxiesBoundaries(t *testing.T) {
	for _, ok := range []string{"10.0.0.0/8", "172.16.0.0/12", "fd00::/16", "::ffff:10.0.0.0/104", "::ffff:1.2.3.4"} {
		if got := parseTrustedProxies(ok); len(got) != 1 {
			t.Errorf("%s должно приниматься: %v", ok, got)
		}
	}
	for _, bad := range []string{"0.0.0.0/7", "::/15", "::ffff:0.0.0.0/96", "::ffff:0:0/80", "128.0.0.0/1", "::ffff:0.0.0.0/103"} {
		if got := parseTrustedProxies(bad); len(got) != 0 {
			t.Errorf("%s должно отбрасываться: %v", bad, got)
		}
	}
}

func TestLoginKeyIPv6Prefix(t *testing.T) {
	if loginKey("2001:db8:1:2::1") != loginKey("2001:db8:1:2:ffff::9") {
		t.Fatal("адреса одной /64 должны давать один ключ")
	}
	if loginKey("2001:db8:1:2::1") == loginKey("2001:db8:1:3::1") {
		t.Fatal("разные /64 должны различаться")
	}
	if loginKey("::ffff:203.0.113.9") != "203.0.113.9" {
		t.Fatal("IPv4 в IPv6-записи должен сводиться к IPv4")
	}
	resetLoginFails()
	for i := 0; i < loginMaxFails; i++ {
		failLogin("2001:db8:1:2::" + strconv.Itoa(i+1))
	}
	if failLogin("2001:db8:1:2:aaaa::1") {
		t.Fatal("ротация внутри /64 не должна обходить лимит")
	}
}

func TestLoginReleaseAndSuccess(t *testing.T) {
	resetLoginFails()
	for i := 0; i < loginMaxFails*2; i++ {
		slot, v := loginEnter("a")
		if v != loginAllowed {
			t.Fatal("рано закрыт")
		}
		slot.done() // без неудачи: не засчитывается
	}
	if !failLogin("a") {
		t.Fatal("снятые попытки не должны считаться")
	}
	slot, _ := loginEnter("a")
	slot.success()
	slot.done()
	loginMu.Lock()
	_, has := loginFails["a"]
	loginMu.Unlock()
	if has {
		t.Fatal("успех должен сбрасывать счётчик")
	}
}

// Параллельные верные запросы с одного адреса не получают отказ и не создают уведомление.
func TestParallelSuccessNoFalseBlock(t *testing.T) {
	resetLoginFails()
	var wg sync.WaitGroup
	var mu sync.Mutex
	denied := 0
	for i := 0; i < loginMaxWaiters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slot, v := loginEnter("office")
			if v != loginAllowed {
				mu.Lock()
				denied++
				mu.Unlock()
				return
			}
			time.Sleep(2 * time.Millisecond)
			slot.success()
			slot.done()
		}()
	}
	wg.Wait()
	if denied != 0 {
		t.Fatalf("отказов у верных параллельных запросов: %d", denied)
	}
	loginMu.Lock()
	n := len(loginBusy)
	loginMu.Unlock()
	if n != 0 {
		t.Fatalf("очередь не очищена: %d", n)
	}
}

// Заблокированный адрес не вытесняется потоком новых адресов.
func TestBlockedSurvivesFlood(t *testing.T) {
	resetLoginFails()
	for i := 0; i < loginMaxFails; i++ {
		failLogin("attacker")
	}
	for i := 0; i < loginTableMax*3; i++ {
		failLogin("flood-" + strconv.Itoa(i))
	}
	if failLogin("attacker") {
		t.Fatal("блок вытеснен потоком адресов")
	}
	loginMu.Lock()
	n := len(loginFails)
	loginMu.Unlock()
	if n > loginTableMax {
		t.Fatalf("таблица %d > потолка", n)
	}
}

// Таблица, целиком забитая блоками, всё равно не растёт выше потолка.
func TestAllBlockedStillCapped(t *testing.T) {
	resetLoginFails()
	for i := 0; i < loginTableMax+500; i++ {
		for j := 0; j < loginMaxFails; j++ {
			failLogin("b-" + strconv.Itoa(i))
		}
	}
	loginMu.Lock()
	n := len(loginFails)
	loginMu.Unlock()
	if n > loginTableMax {
		t.Fatalf("таблица %d > потолка", n)
	}
}

func parallelPosts(r *gin.Engine, path, body string, n int) map[int]int {
	codes := map[int]int{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("POST", path, strings.NewReader(body))
			req.RemoteAddr = "203.0.113.9:4000"
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			mu.Lock()
			codes[w.Code]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	return codes
}

func TestParallelBruteForceLimited(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	resetLoginFails()
	user := db.GetSetting("admin_username", "admin")
	if err := db.UpdateAdminCredentials(user, "pw-for-test"); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	_ = r.SetTrustedProxies(nil)
	r.POST("/login", handleLogin)
	r.POST("/d", handleTOTPDisable)

	codes := parallelPosts(r, "/login", `{"username":"`+user+`","password":"wrong"}`, 200)
	if codes[http.StatusUnauthorized] != loginMaxFails || codes[http.StatusTooManyRequests] != 200-loginMaxFails {
		t.Fatalf("login: %v", codes)
	}

	// отключение 2FA: общий счётчик, параллельный перебор кода
	resetLoginFails()
	secret, _ := totp.NewSecret()
	_ = db.SetSetting("totp_enabled", "1")
	_ = db.SetSetting("totp_secret", secret)
	codes = parallelPosts(r, "/d", `{"password":"pw-for-test","code":"000000"}`, 200)
	if codes[http.StatusForbidden] != loginMaxFails || codes[http.StatusTooManyRequests] != 200-loginMaxFails {
		t.Fatalf("disable: %v", codes)
	}
}

func resetTOTPFails() {
	totpMu.Lock()
	totpFails = nil
	totpMu.Unlock()
}

// Два параллельных запроса с одним верным кодом не проходят оба.
func TestTOTPCodeSingleUseParallel(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	resetTOTPFails()
	secret, _ := totp.NewSecret()
	_ = db.SetSetting("totp_secret", secret)
	_ = db.SetSetting("totp_last_step", "0")
	code, _ := totp.Code(secret, time.Now())
	var wg sync.WaitGroup
	var mu sync.Mutex
	passed := 0
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := totpCheck(code); ok {
				mu.Lock()
				passed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if passed != 1 {
		t.Fatalf("код прошёл %d раз, ждали 1", passed)
	}
}

// Лимит кодов общий для учётной записи: смена адресов не помогает.
func TestTOTPAccountLimit(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	resetTOTPFails()
	secret, _ := totp.NewSecret()
	_ = db.SetSetting("totp_secret", secret)
	_ = db.SetSetting("totp_last_step", "0")
	for i := 0; i < loginMaxFails; i++ {
		if ok, lim := totpCheck("000000"); ok || lim {
			t.Fatalf("попытка %d: ok=%v limited=%v", i, ok, lim)
		}
	}
	code, _ := totp.Code(secret, time.Now())
	if ok, lim := totpCheck(code); ok || !lim {
		t.Fatalf("после лимита ждали limited, получили ok=%v limited=%v", ok, lim)
	}
	resetTOTPFails()
	if ok, _ := totpCheck(code); !ok {
		t.Fatal("верный код после сброса должен проходить")
	}
}

func TestLoginNoticeOncePerBlock(t *testing.T) {
	loginMu.Lock()
	loginNoticed = map[string]time.Time{}
	loginMu.Unlock()
	if !loginNoticeDue("203.0.113.9") || loginNoticeDue("203.0.113.9") {
		t.Fatal("уведомление должно быть одно")
	}
}

// Исчерпание лимита кодов 2FA пишется в аудит один раз на окно, а не на каждый запрос.
func TestTOTPLimitNoticeOnce(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	events.Init()
	loginMu.Lock()
	loginNoticed = map[string]time.Time{}
	loginMu.Unlock()
	for i := 0; i < 5; i++ {
		totpLimitedNotice("admin", "203.0.113.9")
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM audit WHERE action LIKE 'Лимит неверных кодов%'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("записей аудита %d, ждали 1", n)
	}
}
