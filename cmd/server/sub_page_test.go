package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
)

func subTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/sub/:subid", handleSubscription)
	r.HEAD("/sub/:subid", handleSubscription)
	r.GET("/users/:id/devices", handleUserDevices)
	r.DELETE("/users/:id/devices/:did", handleDeleteUserDevice)
	return r
}

func TestSubscriptionPageHeadersAndHead(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	u, err := db.CreateUser("test", 0, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	r := subTestRouter()
	do := func(method, hwid string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/sub/"+u.SubID+"?page=1", nil)
		if hwid != "" {
			req.Header.Set("X-HWID", hwid)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}
	get := do(http.MethodGet, "")
	if get.Code != 200 {
		t.Fatalf("GET: код %d", get.Code)
	}
	for k, want := range map[string]string{"X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
		if get.Header().Get(k) != want {
			t.Errorf("%s = %q", k, get.Header().Get(k))
		}
	}
	if !strings.Contains(get.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Error("в CSP нет frame-ancestors 'none'")
	}
	if get.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(get.Header().Get("Content-Security-Policy"), "form-action 'none'") {
		t.Error("нет nosniff или form-action в CSP")
	}
	head := do(http.MethodHead, "head-dev")
	if head.Code != 200 {
		t.Fatalf("HEAD: код %d", head.Code)
	}
	if l, _ := db.ListDevices(u.ID); len(l) != 0 {
		t.Error("HEAD не должен занимать слот устройства")
	}
}

func TestDeleteDeviceBySlashHWID(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	r := subTestRouter()
	_, _ = db.TouchDevice(1, db.Device{HWID: "a/b"}, 0)
	l, _ := db.ListDevices(1)
	if len(l) != 1 {
		t.Fatal("устройство не записалось")
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/users/1/devices/"+strconv.FormatInt(l[0].ID, 10), nil))
	if rec.Code != 200 {
		t.Fatalf("код %d", rec.Code)
	}
	if l, _ := db.ListDevices(1); len(l) != 0 {
		t.Error("устройство не удалилось")
	}
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/users/1/devices/a%2Fb", nil))
	if rec.Code == 200 {
		t.Error("нечисловой номер должен отклоняться")
	}
}

func TestUnknownAddressesAreIdentical(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	r := subTestRouter()
	setupNotFound(r)
	snap := func(method, path string) string {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		h := rec.Header().Clone()
		h.Del("Date")
		return strconv.Itoa(rec.Code) + "\n" + fmt.Sprint(h) + "\n" + rec.Body.String()
	}
	want := snap(http.MethodGet, "/randompath")
	if !strings.HasPrefix(want, "404") {
		t.Fatalf("эталон: %s", want)
	}
	for _, c := range [][2]string{
		{"GET", "/sub/nope"}, {"HEAD", "/sub/nope"}, {"GET", "/sub/"}, {"GET", "/sub/a/b"}, {"POST", "/sub/x"},
		{"GET", "/sub/nope/"}, {"DELETE", "/sub/nope"}, {"POST", "/randompath"}, {"GET", "/a/b/"},
	} {
		got := snap(c[0], c[1])
		if c[0] == "HEAD" {
			// у HEAD нет тела, остальное (код и заголовки) совпадает
			if strings.SplitN(got, "\n", 3)[0] != "404" || strings.SplitN(got, "\n", 3)[1] != strings.SplitN(want, "\n", 3)[1] {
				t.Errorf("%s %s отличается от /randompath:\n%s\n---\n%s", c[0], c[1], got, want)
			}
			continue
		}
		if got != want {
			t.Errorf("%s %s отличается от /randompath:\n%s\n---\n%s", c[0], c[1], got, want)
		}
	}
}

func TestSubOnlyNotFoundMatchesMainMode(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	r := subTestRouter()
	setupNotFound(r)
	snap := func(h http.Handler, method, path string) string {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		hd := rec.Header().Clone()
		hd.Del("Date")
		return strconv.Itoa(rec.Code) + "\n" + fmt.Sprint(hd) + "\n" + rec.Body.String()
	}
	only := subOnly(r)
	want := snap(r, http.MethodGet, "/randompath")
	for _, c := range [][2]string{
		{"GET", "/randompath"}, {"GET", "/"}, {"POST", "/api/v1/login"}, {"GET", "/sub/nope"}, {"GET", "/sub/"}, {"GET", "/sub/a/b"}, {"POST", "/sub/x"},
	} {
		if got := snap(only, c[0], c[1]); got != want {
			t.Errorf("subOnly %s %s отличается от основного режима:\n%s\n---\n%s", c[0], c[1], got, want)
		}
	}
}
