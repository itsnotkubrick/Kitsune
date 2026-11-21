package main

import (
	"os"
	"strings"
	"testing"
)

func TestRedactReport(t *testing.T) {
	in := "uuid 0b0a8a06-3c1f-4c5e-9d7e-1f2a3b4c5d6e ip 203.0.113.7 v6 2001:db8::1 sub https://vpn.example.com:9443/sub/abcdef0123456789abcdef01 " +
		"key aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxk site example.org file xray.log path /opt/kitsune/data/kitsune.db ok"
	got := redactReport(in)
	for _, bad := range []string{"0b0a8a06", "203.0.113.7", "2001:db8", "vpn.example.com", "abcdef0123456789", "aGVsbG93", "example.org", "/opt/kitsune"} {
		if strings.Contains(got, bad) {
			t.Errorf("в отчёте остался %q: %s", bad, got)
		}
	}
	if !strings.Contains(got, "xray.log") || !strings.HasSuffix(got, "ok") {
		t.Errorf("имя файла и обычный текст должны остаться: %s", got)
	}
}

func TestTailLines(t *testing.T) {
	p := t.TempDir() + "/x.log"
	var sb strings.Builder
	for i := 0; i < 100; i++ {
		sb.WriteString("line\n")
	}
	sb.WriteString("last\n")
	if err := os.WriteFile(p, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	got := tailLines(p, 3)
	if len(got) != 3 || got[2] != "last" {
		t.Errorf("tail: %v", got)
	}
}
