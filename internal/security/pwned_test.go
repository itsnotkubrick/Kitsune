package security

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPwnedUsesKAnonymityAndParsesPadding(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
		w.Write([]byte("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:3\r\nAAAAA11111222223333344444555556666:0\r\n"))
	}))
	defer srv.Close()
	PwnedAPI = srv.URL
	n, err := Pwned("password")
	if err != nil || n != 3 {
		t.Fatalf("%d %v", n, err)
	}
	if gotPath != "/range/5BAA6" || strings.Contains(gotPath, "password") {
		t.Fatalf("наружу должны уходить только 5 символов хеша: %s", gotPath)
	}
	if n, _ := Pwned("точно-нигде-не-встречавшийся-пароль-0"); n != 0 {
		t.Fatalf("не найден: %d", n)
	}
}

func TestPwnedNetworkErrorIsSoft(t *testing.T) {
	PwnedAPI = "http://127.0.0.1:1"
	if _, err := Pwned("x"); err == nil {
		t.Fatal("ошибка сети должна возвращаться вызывающему")
	}
}
