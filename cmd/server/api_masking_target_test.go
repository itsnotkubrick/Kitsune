package main

import (
	"strings"
	"testing"

	"kitsune/internal/selfsteal"
)

func TestMaskingTarget(t *testing.T) {
	// чужой сайт: target не задаётся, REALITY идёт на сам сайт
	if tg, e := maskingTarget("www.yahoo.com", "", false); tg != "" || e != "" {
		t.Errorf("чужой сайт: %q %q", tg, e)
	}
	// свой домен с включённой заглушкой: target – локальная заглушка
	if tg, e := maskingTarget("Pink.My.To", "pink.my.to", true); tg != selfsteal.Addr || e != "" {
		t.Errorf("свой домен с заглушкой: %q %q", tg, e)
	}
	// свой домен без заглушки: отказ с подсказкой, иначе REALITY замкнётся на себя
	tg, e := maskingTarget("pink.my.to", "", true)
	if tg != "" || !strings.Contains(e, "kit selfsteal pink.my.to") {
		t.Errorf("свой домен без заглушки: %q %q", tg, e)
	}
	// чужой домен при включённой заглушке на другом имени: обычный чужой сайт
	if tg, e := maskingTarget("www.yahoo.com", "pink.my.to", false); tg != "" || e != "" {
		t.Errorf("чужой сайт при заглушке на другом домене: %q %q", tg, e)
	}
}
