package stub

import "testing"

func TestRandomIDIsPreset(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 300; i++ {
		id := RandomID("studio")
		if id == "studio" || !Exists(id) {
			t.Fatalf("неверный выбор %q", id)
		}
		seen[id] = true
	}
	if len(seen) < 3 {
		t.Fatalf("выбор слишком однообразный: %v", seen)
	}
}

func TestPickKeepsExistingAndFixesJunk(t *testing.T) {
	if got := Pick("docs"); got != "docs" {
		t.Fatalf("существующая заглушка изменилась: %q", got)
	}
	for _, bad := range []string{"", "мусор", CustomID} { // своя страница без загрузки тоже невалидна
		if got := Pick(bad); !Exists(got) || got == CustomID || got == bad {
			t.Fatalf("для %q выбрано %q", bad, got)
		}
	}
	SetCustom("<html>mine</html>")
	defer SetCustom("")
	if got := Pick(CustomID); got != CustomID {
		t.Fatalf("загруженная страница не должна заменяться: %q", got)
	}
}

func TestHTMLFallback(t *testing.T) {
	if HTML("нет такой") != Templates[0].html || Title("docs") != "Документация" {
		t.Fatal("неизвестный идентификатор или подпись")
	}
	for _, tpl := range Templates {
		if HTML(tpl.ID) == "" || !Exists(tpl.ID) {
			t.Fatalf("заглушка %q недоступна", tpl.ID)
		}
	}
	if l := ListWith("studio"); len(l) != len(Templates) {
		t.Fatalf("список изменился: %d", len(l))
	}
}
