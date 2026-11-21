package backup

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

func seal(t *testing.T, data []byte, pw string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewEncryptWriter(&buf, pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestEncryptRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, encChunk - 1, encChunk, encChunk + 1, 3*encChunk + 17} {
		data := make([]byte, size)
		_, _ = rand.Read(data)
		enc := seal(t, data, "пароль-12345")
		if !IsEncrypted(enc) || (size > 16 && bytes.Contains(enc, data[:16])) {
			t.Fatalf("размер %d: данные не зашифрованы", size)
		}
		r, err := NewDecryptReader(bytes.NewReader(enc), "пароль-12345")
		if err != nil {
			t.Fatalf("размер %d: %v", size, err)
		}
		got, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("размер %d: данные не совпали (%v)", size, err)
		}
	}
}

func TestDecryptRejectsWrongPasswordAndTampering(t *testing.T) {
	data := bytes.Repeat([]byte("kitsune"), 40000) // несколько кусков
	enc := seal(t, data, "верный-пароль")
	if _, err := NewDecryptReader(bytes.NewReader(enc), "другой-пароль"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("неверный пароль: %v", err)
	}
	// обрезанный файл: последний кусок не помечен как последний
	cut := enc[:len(enc)-(encChunk+16)]
	if r, err := NewDecryptReader(bytes.NewReader(cut), "верный-пароль"); err == nil {
		if _, err = io.ReadAll(r); err == nil {
			t.Fatal("обрезанный файл прочитан без ошибки")
		}
	}
	// испорченный байт в середине
	bad := append([]byte(nil), enc...)
	bad[len(bad)/2] ^= 0xff
	if r, err := NewDecryptReader(bytes.NewReader(bad), "верный-пароль"); err == nil {
		if _, err = io.ReadAll(r); err == nil {
			t.Fatal("испорченный файл прочитан без ошибки")
		}
	}
}
