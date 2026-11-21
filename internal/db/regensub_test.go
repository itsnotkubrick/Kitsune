package db

import (
	"database/sql"
	"errors"
	"testing"
)

func TestRegenSubID(t *testing.T) {
	t.Chdir(t.TempDir())
	InitDB()
	defer DB.Close()
	u, err := CreateUser("regen", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	nsub, err := RegenSubID(u.ID)
	if err != nil || nsub == "" || nsub == u.SubID {
		t.Fatalf("новая ссылка: %q, %v", nsub, err)
	}
	if got, err := GetUserBySubID(u.SubID); err == nil && got != nil {
		t.Error("старая ссылка должна перестать работать")
	}
	got, err := GetUserBySubID(nsub)
	if err != nil || got == nil || got.UUID != u.UUID || got.Password != u.Password {
		t.Errorf("новая ссылка ведёт к тому же пользователю с теми же ключами: %+v, %v", got, err)
	}
	if _, err := RegenSubID(999999); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("несуществующий пользователь: %v", err)
	}
}
