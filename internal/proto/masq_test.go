package proto

import "testing"

// Ответ Hysteria2 постороннему: своё поле главнее, иначе локальный «обычный сайт» панели, иначе встроенная страница.
func TestHysteriaMasqueradeChoice(t *testing.T) {
	env := Env{StubID: "nginx", MasqURL: "http://127.0.0.1:10398"}

	if m := (Settings{}).hysteriaMasquerade(env); m["type"] != "proxy" || m["url"] != "http://127.0.0.1:10398" {
		t.Fatalf("по умолчанию ожидался proxy на локальный сайт: %v", m)
	}
	if m := (Settings{Masquerade: "https://news.example.org/"}).hysteriaMasquerade(env); m["type"] != "proxy" || m["url"] != "https://news.example.org/" {
		t.Fatalf("своё поле с адресом главнее: %v", m)
	}
	if m := (Settings{Masquerade: "<html>моя</html>"}).hysteriaMasquerade(env); m["type"] != "string" || m["content"] != "<html>моя</html>" {
		t.Fatalf("своя страница остаётся как есть: %v", m)
	}
	// слушатель не запущен (порт занят): встроенная заглушка, как раньше
	if m := (Settings{}).hysteriaMasquerade(Env{StubID: "nginx"}); m["type"] != "string" {
		t.Fatalf("без слушателя ожидалась встроенная страница: %v", m)
	}
	if m := (Settings{}).hysteriaMasquerade(Env{}); m != nil {
		t.Fatalf("без заглушки маскировки нет: %v", m)
	}
}
