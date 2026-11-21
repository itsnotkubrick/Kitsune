package sub

import "testing"

func TestDetectFormat(t *testing.T) {
	cases := []struct {
		format, ua, want string
	}{
		// явный параметр сильнее User-Agent
		{"clash", "", FormatClash},
		{"singbox", "", FormatSingbox},
		{"raw", "clash.meta", FormatRaw},
		{"clash", "HiddifyNext/4.0.5", FormatClash},
		// клиенты на Mihomo и sing-box
		{"", "clash-verge/v2.0", FormatClash},
		{"", "FlClash/0.8", FormatClash},
		{"", "mihomo/1.19", FormatClash},
		{"", "sing-box 1.14.3", FormatSingbox},
		// Hiddify называет себя и Clash, и sing-box: ему нужен обычный список ссылок
		{"", "HiddifyNext/4.0.5 (android) ClashMeta", FormatRaw},
		{"", "Hiddify/4.0.5 clash.meta sing-box", FormatRaw},
		{"", "hiddifynext/2.5", FormatRaw},
		// остальные
		{"", "v2rayN/7.0", FormatRaw},
		{"", "Happ/1.0", FormatRaw},
		{"", "", FormatRaw},
	}
	for _, c := range cases {
		if got := DetectFormat(c.format, c.ua); got != c.want {
			t.Errorf("DetectFormat(%q, %q) = %q, ожидалось %q", c.format, c.ua, got, c.want)
		}
	}
}
