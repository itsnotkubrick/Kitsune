package main

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"kitsune/internal/proto"
)

func TestBuildSettingsHeaderKey(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	hx := hex.EncodeToString(raw)
	for name, in := range map[string]string{"hex": hx, "HEX": strings.ToUpper(hx), "base64": base64.StdEncoding.EncodeToString(raw)} {
		s, err := buildSettings(proto.AWG3, proto.Settings{}, map[string]any{"header_key": in})
		if err != nil || s.HeaderKey != hx {
			t.Fatalf("%s: ключ %q, ошибка %v", name, s.HeaderKey, err)
		}
	}
	for _, bad := range []string{"abc", strings.Repeat("z", 64), hx[:62], base64.StdEncoding.EncodeToString(raw[:16])} {
		if _, err := buildSettings(proto.AWG3, proto.Settings{}, map[string]any{"header_key": bad}); err == nil {
			t.Fatalf("ключ %q должен быть отклонён", bad)
		}
	}
	// сохранённый ключ не трогается, пока поле не меняют
	old := proto.Settings{HeaderKey: hx}
	s, err := buildSettings(proto.AWG3, old, map[string]any{"mtu": "1300"})
	if err != nil || s.HeaderKey != hx {
		t.Fatalf("сохранённый ключ изменился: %q %v", s.HeaderKey, err)
	}
}

func TestBuildSettingsHeaderKeyBlank(t *testing.T) {
	old := proto.Settings{HeaderKey: strings.Repeat("ab", 32)}
	s, err := buildSettings(proto.AWG3, old, map[string]any{"header_key": "   "})
	if err != nil || s.HeaderKey != old.HeaderKey {
		t.Fatalf("из пробелов ключ должен остаться прежним: %q %v", s.HeaderKey, err)
	}
}
