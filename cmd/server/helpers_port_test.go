package main

import "testing"

func TestPickRandomPortIsNotAProgression(t *testing.T) {
	seen := map[int]bool{}
	for i := 0; i < 40; i++ {
		p := pickRandomPort(func(int) bool { return true })
		if p < 10240 || p >= 60000 {
			t.Fatalf("порт %d вне диапазона", p)
		}
		seen[p] = true
	}
	if len(seen) < 30 {
		t.Fatalf("порты почти не меняются: %d разных из 40", len(seen))
	}
}

func TestPickRandomPortSkipsBusyAndFallsBack(t *testing.T) {
	free := func(p int) bool { return p == 31337 } // свободен один-единственный порт
	if got := pickRandomPort(free); got != 31337 {
		t.Fatalf("ждали единственный свободный 31337, получили %d", got)
	}
	if got := pickRandomPort(func(int) bool { return false }); got != 0 {
		t.Fatalf("свободных нет, ждали 0, получили %d", got)
	}
}
