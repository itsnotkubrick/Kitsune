package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
)

func resetSubFails() {
	subMu.Lock()
	subFails = map[string][]time.Time{}
	subMu.Unlock()
}

func subRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	_ = r.SetTrustedProxies(trustedProxiesFromEnv())
	setupNotFound(r)
	r.GET("/sub/:subid", handleSubscription)
	r.HEAD("/sub/:subid", handleSubscription)
	return r
}

func subGet(r *gin.Engine, remote, id string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/sub/"+id, nil)
	req.RemoteAddr = remote
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestSubIDLengthAndLegacyLinks(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	resetSubFails()
	u, err := db.CreateUser("newbie", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(u.SubID) {
		t.Fatalf("идентификатор подписки %q: ждали 32 hex-символа (128 бит)", u.SubID)
	}
	// старая короткая ссылка продолжает работать
	if _, err := db.DB.Exec("UPDATE users SET sub_id = ? WHERE id = ?", "0123456789abcdef", u.ID); err != nil {
		t.Fatal(err)
	}
	w := subGet(subRouter(), "203.0.113.9:4000", "0123456789abcdef", nil)
	if w.Header().Get("Subscription-Userinfo") == "" {
		t.Fatalf("старая ссылка не открылась: %d %q", w.Code, w.Body.String())
	}
}

func TestSubUnknownLooksLikeAnyOtherPath(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	resetSubFails()
	r := subRouter()
	w := subGet(r, "203.0.113.9:4000", "doesnotexist", nil)
	other := httptest.NewRecorder()
	notFound(func() *gin.Context {
		c, _ := gin.CreateTestContext(other)
		c.Request = httptest.NewRequest("GET", "/x", nil)
		return c
	}())
	if w.Code != http.StatusNotFound || w.Body.String() != other.Body.String() || w.Header().Get("Content-Type") != other.Header().Get("Content-Type") {
		t.Fatalf("ответ на неизвестный идентификатор: %d %q %q, ждали как у остальных адресов: %d %q %q",
			w.Code, w.Header().Get("Content-Type"), w.Body.String(), other.Code, other.Header().Get("Content-Type"), other.Body.String())
	}
}

func TestSubBruteForceLimited(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	resetSubFails()
	u, err := db.CreateUser("victim", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := subRouter()
	// подмена X-Forwarded-For не меняет адрес; после лимита закрыты все запросы адреса, в том числе с верным идентификатором
	for i := 0; i < subMaxFails; i++ {
		w := subGet(r, "203.0.113.9:4000", "guess"+strconv.Itoa(i), map[string]string{"X-Forwarded-For": "10.0.0." + strconv.Itoa(i)})
		if w.Code != http.StatusNotFound {
			t.Fatalf("попытка %d: %d", i, w.Code)
		}
	}
	for _, id := range []string{"guess-more", u.SubID} {
		w := subGet(r, "203.0.113.9:4000", id, nil)
		if w.Code != http.StatusNotFound || w.Header().Get("Subscription-Userinfo") != "" {
			t.Fatalf("%s: ждали 404 без данных подписки, получили %d", id, w.Code)
		}
	}
	// другой адрес не затронут
	if w := subGet(r, "198.51.100.7:4000", u.SubID, nil); w.Header().Get("Subscription-Userinfo") == "" {
		t.Fatalf("чужой адрес закрыт: %d", w.Code)
	}
}

func TestSubLimitIPv6ByNetwork(t *testing.T) {
	resetSubFails()
	for i := 0; i < subMaxFails; i++ {
		subFail("2001:db8:1:2::" + strconv.Itoa(i+1))
	}
	if !subBlocked("2001:db8:1:2:ffff::9") {
		t.Fatal("адреса из одной сети /64 должны считаться одним")
	}
	if subBlocked("2001:db8:1:3::1") {
		t.Fatal("соседняя сеть /64 закрыта зря")
	}
}

func TestSubTableCapped(t *testing.T) {
	resetSubFails()
	for i := 0; i < subTableMax*2; i++ {
		subFail("ip-" + strconv.Itoa(i))
	}
	subMu.Lock()
	n := len(subFails)
	subMu.Unlock()
	if n > subTableMax {
		t.Fatalf("таблица выросла до %d, потолок %d", n, subTableMax)
	}
}

// Закрытый адрес получает тот же ответ, что и любой неизвестный путь: код, заголовки (кроме Date) и тело совпадают
// для GET, HEAD и POST, в обычном режиме и в режиме «только подписки».
func TestSubBlockedLooksLikeUnknownPath(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	resetSubFails()
	u, err := db.CreateUser("victim", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := subRouter()
	for i := 0; i < subMaxFails; i++ {
		subFail("203.0.113.9")
	}
	if !subBlocked("203.0.113.9") {
		t.Fatal("адрес должен быть закрыт")
	}
	serve := func(h http.Handler, method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "203.0.113.9:4000"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	handlers := map[string]http.Handler{"обычный": r, "только подписки": subOnly(r)}
	for mode, h := range handlers {
		for _, method := range []string{"GET", "HEAD", "POST"} {
			want := serve(h, method, "/randompath")
			for _, path := range []string{"/sub/" + u.SubID, "/sub/unknown"} {
				got := serve(h, method, path)
				if got.Code != want.Code || got.Body.String() != want.Body.String() {
					t.Errorf("%s %s %s: %d %q, ждали %d %q", mode, method, path, got.Code, got.Body.String(), want.Code, want.Body.String())
				}
				gh, wh := got.Header().Clone(), want.Header().Clone()
				gh.Del("Date")
				wh.Del("Date")
				if !reflect.DeepEqual(gh, wh) {
					t.Errorf("%s %s %s: заголовки %v, ждали %v", mode, method, path, gh, wh)
				}
			}
		}
	}
}
