package importer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const apiToken = "tok-SECRET-123"

// fakeMarzban – сервер с API Marzban: логин, список пользователей постранично, настройки Xray.
func fakeMarzban(t *testing.T, users int, coreStatus int, cfg string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Method != http.MethodPost || r.PostForm.Get("username") != "root" || r.PostForm.Get("password") != "pw-SECRET" {
			http.Error(w, `{"detail":"bad"}`, http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, `{"access_token":%q,"token_type":"bearer"}`, apiToken)
	})
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+apiToken {
				http.Error(w, `{"detail":"no"}`, http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("/api/users", auth(func(w http.ResponseWriter, r *http.Request) {
		var off, lim int
		fmt.Sscan(r.URL.Query().Get("offset"), &off)
		fmt.Sscan(r.URL.Query().Get("limit"), &lim)
		var list []map[string]any
		for i := off; i < off+lim && i < users; i++ {
			list = append(list, map[string]any{"username": fmt.Sprintf("user%d", i), "status": "active", "used_traffic": 1000 + i, "data_limit": 5 << 30,
				"expire": 1800000000, "note": "n", "subscription_url": "https://x/sub/SUBSECRET",
				"proxies": map[string]any{"vless": map[string]any{"id": uuidA, "flow": "xtls-rprx-vision"}, "trojan": map[string]any{"password": "trojan-pw"}}})
		}
		json.NewEncoder(w).Encode(map[string]any{"users": list, "total": users})
	}))
	mux.HandleFunc("/api/core/config", auth(func(w http.ResponseWriter, r *http.Request) {
		if coreStatus != 200 {
			http.Error(w, "{}", coreStatus)
			return
		}
		w.Write([]byte(cfg))
	}))
	mux.HandleFunc("/api/inbounds", auth(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vless":[{"tag":"VLESS TCP","protocol":"vless","network":"tcp","tls":"reality","port":443}]}`))
	}))
	return httptest.NewServer(mux)
}

func TestParseAPIURL(t *testing.T) {
	ok := map[string]string{
		"https://panel.example.com:8000":       "https://panel.example.com:8000",
		"https://panel.example.com/dashboard/": "https://panel.example.com",
		"http://localhost:8000":                "http://localhost:8000",
		"http://127.0.0.1:8000/":               "http://127.0.0.1:8000",
		"http://[::1]:8000":                    "http://[::1]:8000",
		"https://10.0.0.5:8000/marzban":        "https://10.0.0.5:8000/marzban",
	}
	for in, want := range ok {
		u, err := ParseAPIURL(in)
		if err != nil || u.String() != want {
			t.Errorf("%q: %v %v", in, u, err)
		}
	}
	for _, in := range []string{"", "ftp://x.com", "http://panel.example.com", "http://10.0.0.5:8000", "https://user:pw@x.com", "https://x.com?a=1",
		"https://x.com/#f", "https://*.x.com", "https://x.com:99999", "https://x.com:0", "//x.com", "https://x .com", "https://x.com/../a", "x.com", "https://", "file:///etc/passwd",
		"http://localhost.evil.com"} {
		if _, err := ParseAPIURL(in); err == nil {
			t.Errorf("%q: ждали отказ", in)
		}
	}
}

func TestMarzbanAPIUsersAndConfig(t *testing.T) {
	srv := fakeMarzban(t, 250, 200, jsonOf(t, m{"inbounds": []m{{"tag": "R", "port": 443, "protocol": "vless", "settings": m{"clients": []m{}},
		"streamSettings": m{"network": "tcp", "security": "reality", "realitySettings": m{"serverNames": []string{"www.example.com"}, "dest": "www.example.com:443"}}}}}))
	defer srv.Close()
	for name, auth := range map[string]APIAuth{"token": {Token: apiToken}, "login": {Username: "root", Password: "pw-SECRET"}} {
		data, err := ReadMarzbanAPI(context.Background(), srv.URL, auth)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(data.Users) != 250 {
			t.Fatalf("%s: пользователей %d (постраничное чтение)", name, len(data.Users))
		}
		u := data.Users[7]
		if u.Name != "user7" || u.UUID != uuidA || u.Password != "trojan-pw" || !u.Vision || u.Used != 1007 || u.ExpiryMs != 1800000000000 || u.TrafficLimit != 5<<30 {
			t.Errorf("%s: %+v", name, u)
		}
		if len(data.Inbounds) != 1 || data.Inbounds[0].Kind == "" {
			t.Errorf("%s: подключения из настроек Xray: %+v", name, data.Inbounds)
		}
		raw, _ := json.Marshal(data)
		for _, secret := range []string{apiToken, "pw-SECRET", "SUBSECRET"} {
			if strings.Contains(string(raw), secret) {
				t.Errorf("%s: секрет %q в данных", name, secret)
			}
		}
	}
}

func TestMarzbanAPIWithoutConfigRights(t *testing.T) {
	srv := fakeMarzban(t, 3, http.StatusForbidden, "")
	defer srv.Close()
	data, err := ReadMarzbanAPI(context.Background(), srv.URL, APIAuth{Token: apiToken})
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Users) != 3 || len(data.Inbounds) != 1 || data.Inbounds[0].Kind != "" || data.Inbounds[0].SkipReason == "" {
		t.Fatalf("%+v", data)
	}
	if !hasWarn(data.Notes, "нет прав") {
		t.Errorf("нет пояснения о правах: %v", data.Notes)
	}
}

func TestMarzbanAPIErrors(t *testing.T) {
	srv := fakeMarzban(t, 1, 200, "{}")
	defer srv.Close()
	for name, a := range map[string]APIAuth{
		"wrong password": {Username: "root", Password: "no"},
		"wrong token":    {Token: "zzz"},
		"empty":          {},
		"bad token":      {Token: "a b"},
	} {
		_, err := ReadMarzbanAPI(context.Background(), srv.URL, a)
		if err == nil {
			t.Errorf("%s: ждали ошибку", name)
			continue
		}
		for _, secret := range []string{"pw-SECRET", "zzz", apiToken, "no"} {
			if secret != "no" && strings.Contains(err.Error(), secret) {
				t.Errorf("%s: секрет в ошибке: %v", name, err)
			}
		}
	}
	if _, err := ReadMarzbanAPI(context.Background(), "http://example.com", APIAuth{Token: "t"}); err == nil {
		t.Error("http не к localhost должен отклоняться")
	}
	// Закрытый порт и мусор вместо API.
	if _, err := ReadMarzbanAPI(context.Background(), "http://127.0.0.1:1", APIAuth{Token: "t"}); err == nil {
		t.Error("недоступный адрес")
	}
	junk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>")) }))
	defer junk.Close()
	if _, err := ReadMarzbanAPI(context.Background(), junk.URL, APIAuth{Token: "t"}); err == nil {
		t.Error("не JSON")
	}
}

func TestMarzbanAPIRedirects(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("токен ушёл на другой адрес")
		}
		w.Write([]byte(`{"users":[],"total":0}`))
	}))
	defer other.Close()
	// 127.0.0.1 и localhost – разные хосты: переход между ними запрещён.
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.Replace(other.URL, "127.0.0.1", "localhost", 1)+"/api/users", http.StatusTemporaryRedirect)
	}))
	defer src.Close()
	if _, err := ReadMarzbanAPI(context.Background(), src.URL, APIAuth{Token: "t"}); err == nil {
		t.Error("редирект на другой хост должен отклоняться")
	}
	if hits.Load() != 0 {
		t.Errorf("запросов на чужой адрес: %d", hits.Load())
	}
	// Переход в пределах того же адреса разрешён.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/api/v2/users", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/api/v2/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer t" {
			t.Error("токен не передан при переходе в пределах адреса")
		}
		w.Write([]byte(`{"users":[{"username":"a"}],"total":1}`))
	})
	same := httptest.NewServer(mux)
	defer same.Close()
	d, err := ReadMarzbanAPI(context.Background(), same.URL, APIAuth{Token: "t"})
	if err != nil || len(d.Users) != 1 {
		t.Errorf("переход в пределах адреса: %v %v", d, err)
	}
}

func TestMarzbanAPILimitsAndTimeout(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"users":[{"username":"a","note":"`))
		chunk := []byte(strings.Repeat("a", 1<<20))
		for i := 0; i < apiMaxResponse>>20+2; i++ {
			w.Write(chunk)
		}
		w.Write([]byte(`"}],"total":1}`))
	}))
	defer big.Close()
	if _, err := ReadMarzbanAPI(context.Background(), big.URL, APIAuth{Token: "t"}); err == nil || !strings.Contains(err.Error(), "слишком большой") {
		t.Errorf("большой ответ: %v", err)
	}
	old := apiRequestTimeout
	apiRequestTimeout = 300 * time.Millisecond
	defer func() { apiRequestTimeout = old }()
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(2 * time.Second) }))
	defer slow.Close()
	start := time.Now()
	if _, err := ReadMarzbanAPI(context.Background(), slow.URL, APIAuth{Token: "t"}); err == nil || time.Since(start) > 1500*time.Millisecond {
		t.Errorf("таймаут: %v за %v", err, time.Since(start))
	}
	// Больше пользователей, чем разрешено.
	many := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"users":[],"total":100001}`)) }))
	defer many.Close()
	if _, err := ReadMarzbanAPI(context.Background(), many.URL, APIAuth{Token: "t"}); err == nil {
		t.Error("слишком много пользователей")
	}
}

func TestMarzbanAPITLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/users" {
			w.Write([]byte(`{"users":[{"username":"tls-user"}],"total":1}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	// Сертификат тестового сервера не доверенный: подключение отклоняется, проверку не отключить.
	if _, err := ReadMarzbanAPI(context.Background(), srv.URL, APIAuth{Token: "t"}); err == nil || !strings.Contains(err.Error(), "сертификат") {
		t.Fatalf("недоверенный сертификат: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	apiTransportHook = func(tr *http.Transport) {
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	defer func() { apiTransportHook = nil }()
	d, err := ReadMarzbanAPI(context.Background(), srv.URL, APIAuth{Token: "t"})
	if err != nil || len(d.Users) != 1 || d.Users[0].Name != "tls-user" {
		t.Fatalf("%v %v", d, err)
	}
}

func TestMarzbanAPIRunsThroughImport(t *testing.T) {
	srv := fakeMarzban(t, 4, 200, `{"inbounds":[]}`)
	defer srv.Close()
	data, err := ReadMarzbanAPI(context.Background(), srv.URL, APIAuth{Token: apiToken})
	if err != nil {
		t.Fatal(err)
	}
	k := openKitsune(t)
	rep, err := Run(k, data, opts(true, false))
	if err != nil {
		t.Fatal(err)
	}
	if rep.UserSum.Create != 1 { // у всех один UUID: остальные учтены как дубли
		t.Logf("итоги: %+v", rep.UserSum)
	}
	if count(t, k, "users") == 0 {
		t.Error("пользователи не созданы")
	}
	if _, err := os.Stat("import-tmp"); err == nil {
		t.Log("import-tmp есть")
	}
}
