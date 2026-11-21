package db

import (
	"testing"
	"time"
)

func TestPassportHistory(t *testing.T) {
	t.Chdir(t.TempDir())
	InitDB()
	defer DB.Close()
	w := []PassportLine{{Level: "warn", Text: "Панель отвечает на любой адрес"}}
	if err := AddPassport(90, 0, 1, w); err != nil {
		t.Fatal(err)
	}
	// то же самое сразу после: не дублируется
	_ = AddPassport(90, 0, 1, w)
	if n := len(GetPassport(10)); n != 1 {
		t.Fatalf("повтор записан: %d записей", n)
	}
	time.Sleep(2 * time.Millisecond)
	// изменилось: пишется сразу
	_ = AddPassport(100, 0, 0, nil)
	h := GetPassport(10)
	if len(h) != 2 || h[0].Score != 90 || h[1].Score != 100 || len(h[1].Lines) != 0 {
		t.Fatalf("история: %+v", h)
	}
	// старые записи чистятся
	_, _ = DB.Exec(`INSERT INTO passport_history (at, score) VALUES (?, 50)`, time.Now().AddDate(0, 0, -200).UnixMilli())
	time.Sleep(2 * time.Millisecond)
	_ = AddPassport(80, 0, 2, w)
	for _, r := range GetPassport(50) {
		if r.Score == 50 {
			t.Fatal("запись старше 90 дней не удалена")
		}
	}
}
