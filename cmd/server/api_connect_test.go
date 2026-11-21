package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
)

func connectRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/sub/:subid/connect", handleConnectPage)
	r.POST("/sub/:subid/connect/e/:event", handleConnectEvent)
	return r
}

func TestConnectPageAndEvents(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	u, err := db.CreateUser("anna", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := connectRouter()
	do := func(method, path, ua string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("User-Agent", ua)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}
	rec := do("GET", "/sub/"+u.SubID+"/connect", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"detected":"ios"`) || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "connect-src 'self'") {
		t.Fatalf("страница: код %d", rec.Code)
	}
	if do("POST", "/sub/"+u.SubID+"/connect/e/store", "x").Code != http.StatusNoContent {
		t.Error("store не принят")
	}
	if do("POST", "/sub/"+u.SubID+"/connect/e/sub", "x").Code != http.StatusNotFound {
		t.Error("чужое событие должно быть отклонено: sub пишет только сервер")
	}
	if do("GET", "/sub/nope/connect", "x").Code != http.StatusNotFound {
		t.Error("неизвестная ссылка должна давать 404")
	}
	steps := connectProgress(*getUser(t, u.ID))
	if !steps[0].Done || !steps[1].Done || steps[2].Done || steps[0].Note != "ios" {
		t.Errorf("этапы: %+v", steps)
	}
}

func getUser(t *testing.T, id int) *db.User {
	t.Helper()
	u, err := db.GetUser(id)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestAppFromUA(t *testing.T) {
	for ua, want := range map[string]string{"Happ/2.1 iOS": "Happ", "Hiddify/2.0": "Hiddify", "v2rayNG/1.9": "v2rayNG", "curl/8.1": "curl"} {
		if got := appFromUA(ua); got != want {
			t.Errorf("%q: %q, хотели %q", ua, got, want)
		}
	}
}
