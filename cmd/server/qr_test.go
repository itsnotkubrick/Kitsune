package main

import (
	"strings"
	"testing"
)

func TestTerminalQR(t *testing.T) {
	out := terminalQR("otpauth://totp/Kitsune:admin?secret=ABC")
	if strings.Count(out, "\n") < 10 || !strings.Contains(out, "█") {
		t.Fatalf("QR не нарисован:\n%s", out)
	}
}
