package proto

import (
	"encoding/json"
	"strings"
	"testing"

	"kitsune/internal/db"
)

func TestMTProtoUserSecretSalt(t *testing.T) {
	a := MTProtoUserSecret("salt-one", "uuid-1")
	if len(a) != 32 {
		t.Fatalf("длина секрета %d", len(a))
	}
	if a != MTProtoUserSecret("salt-one", "uuid-1") {
		t.Fatal("одна соль и один UUID должны давать один секрет")
	}
	if a == MTProtoUserSecret("salt-two", "uuid-1") {
		t.Fatal("разные соли должны давать разные секреты")
	}
	if a == MTProtoUserSecret("salt-one", "uuid-2") {
		t.Fatal("разные пользователи должны получать разные секреты")
	}
}

// Соль не входит ни в настройки, ни в данные пользователя, ни в ссылки: в JSON API её быть не может.
func TestMTProtoSaltNotInJSON(t *testing.T) {
	const salt = "SALTSALTSALT-marker"
	secret := MTProtoUserSecret(salt, "uuid-1")
	s := Settings{Engine: "telemt"}
	if err := s.Fill(MTProto); err != nil {
		t.Fatal(err)
	}
	u := db.User{UUID: "uuid-1", Name: "alice"}
	in := db.Inbound{Kind: string(MTProto), Port: 8447, Settings: s.JSON()}
	for _, v := range []any{s, u, in} {
		b, _ := json.Marshal(v)
		if strings.Contains(string(b), salt) || strings.Contains(string(b), secret) {
			t.Fatalf("соль или секрет попали в JSON: %s", b)
		}
	}
}

func TestMTProtoUserSecretEmptyWithoutSalt(t *testing.T) {
	if MTProtoUserSecret("", "uuid-1") != "" {
		t.Fatal("без соли секрет выдаваться не должен")
	}
}
