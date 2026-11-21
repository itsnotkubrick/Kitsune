package importer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Невалидный пароль в первом подключении, валидный во втором: предупреждения «не перенесён» нет.
func TestImportMoreBadPasswordThenValidXUI(t *testing.T) {
	p := imdb(t,
		imrow{1, "A", 8444, "trojan", m{"clients": []m{{"password": "bad pass", "email": "alice", "subId": "sa"}}}, nil},
		imrow{2, "B", 8445, "trojan", m{"clients": []m{{"password": "goodpass", "email": "alice-2", "subId": "sa"}}}, nil},
	)
	data, err := Read3XUI(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Users) != 1 || data.Users[0].Password != "goodpass" {
		t.Fatalf("%+v", data.Users)
	}
	for _, w := range data.Users[0].Warnings {
		if w == badSecretWarn {
			t.Errorf("лишнее предупреждение: %v", data.Users[0].Warnings)
		}
	}
}

func TestImportMoreBadPasswordThenValidMarzban(t *testing.T) {
	u, ok := marzbanUser(map[string]any{"username": "alice"}, []marzbanProxy{{password: "bad pass"}, {password: "goodpass"}})
	if !ok || u.Password != "goodpass" {
		t.Fatalf("%+v", u)
	}
	for _, w := range u.Warnings {
		if w == badSecretWarn {
			t.Errorf("лишнее предупреждение: %v", u.Warnings)
		}
	}
	u, _ = marzbanUser(map[string]any{"username": "bob"}, []marzbanProxy{{password: "bad pass"}})
	if len(u.Warnings) != 1 || u.Warnings[0] != badSecretWarn {
		t.Errorf("ожидалось одно предупреждение: %v", u.Warnings)
	}
}

// Marzban отдал всех, но одно имя некорректно: примечание про разбор, а не про страницы.
func TestImportMoreAPIDroppedUsersNote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/users" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"total":3,"users":[{"username":"a"},{"username":""},{"username":"c"}]}`)
	}))
	defer srv.Close()
	d, err := ReadMarzbanAPI(context.Background(), srv.URL, APIAuth{Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(d.Notes, "\n")
	if len(d.Users) != 2 || !strings.Contains(all, "Прочитано 2 из 3") || !strings.Contains(all, "пропущено при разборе") {
		t.Errorf("%d %v", len(d.Users), d.Notes)
	}
	if strings.Contains(all, "не все страницы") {
		t.Errorf("ложное утверждение про страницы: %v", d.Notes)
	}
}
