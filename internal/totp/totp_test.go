package totp

import (
	"testing"
	"time"
)

// Контрольные значения RFC 6238 (секрет «12345678901234567890», SHA-1, 6 цифр).
func TestRFC6238Vectors(t *testing.T) {
	secret := enc.EncodeToString([]byte("12345678901234567890"))
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037"} {
		got, err := Code(secret, time.Unix(unix, 0))
		if err != nil || got != want {
			t.Fatalf("t=%d: %s, ожидалось %s (%v)", unix, got, want, err)
		}
	}
}

func TestVerifyWindowAndReplayStep(t *testing.T) {
	secret, _ := NewSecret()
	now := time.Unix(1_800_000_000, 0)
	c, _ := Code(secret, now)
	step, ok := Verify(secret, c, now)
	if !ok || step != Step(now) {
		t.Fatalf("код текущего интервала: %v %d", ok, step)
	}
	prev, _ := Code(secret, now.Add(-30*time.Second))
	if _, ok := Verify(secret, prev, now); !ok {
		t.Fatal("допуск на предыдущий интервал")
	}
	old, _ := Code(secret, now.Add(-120*time.Second))
	if _, ok := Verify(secret, old, now); ok {
		t.Fatal("старый код принимать нельзя")
	}
	for _, bad := range []string{"", "12345", "abcdef", "1234567"} {
		if _, ok := Verify(secret, bad, now); ok {
			t.Fatalf("%q принято", bad)
		}
	}
	if _, ok := Verify(secret, c[:3]+" "+c[3:], now); !ok {
		t.Fatal("пробелы в коде допустимы")
	}
}
