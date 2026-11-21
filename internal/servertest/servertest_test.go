package servertest

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerdict(t *testing.T) {
	for _, c := range []struct {
		in   []Level
		want string
	}{
		{nil, "ok"}, {[]Level{OK, Info, Skip}, "ok"}, {[]Level{OK, Warn}, "caveats"}, {[]Level{Warn, Bad, OK}, "bad"}, {[]Level{Skip, Skip}, "ok"},
	} {
		var rs []Result
		for _, l := range c.in {
			rs = append(rs, Result{Level: l})
		}
		if got := Verdict(rs); got != c.want {
			t.Errorf("%v: %s, ожидалось %s", c.in, got, c.want)
		}
	}
	if !strings.Contains(VerdictText("bad", RU), "не подходит") || !strings.Contains(VerdictText("bad", EN), "Not suitable") {
		t.Error("тексты сводки")
	}
}

func TestRunKeepsOrderAndRecoversFromPanic(t *testing.T) {
	var seen []string
	tests := []Test{
		{ID: "a", Group: "g", Run: func(context.Context, Lang) Result { return Result{Level: OK, Title: "A"} }},
		{ID: "boom", Group: "g", Run: func(context.Context, Lang) Result { panic("сбой") }},
		{ID: "c", Group: "g", Run: func(context.Context, Lang) Result { return Result{Level: Info, Title: "C"} }},
	}
	rep := Run(context.Background(), tests, RU, func(r Result) { seen = append(seen, r.ID) })
	if len(rep.Results) != 3 || strings.Join(seen, ",") != "a,boom,c" {
		t.Fatalf("порядок или число результатов: %v", seen)
	}
	if rep.Results[1].Level != Warn || !strings.Contains(rep.Results[1].Detail, "сбой") || rep.Results[0].ID != "a" || rep.Results[0].Group != "g" {
		t.Fatalf("паника не обработана: %+v", rep.Results)
	}
	if rep.Verdict != "caveats" {
		t.Fatalf("сводка %s", rep.Verdict)
	}
}

func TestRunTimeoutAndCancel(t *testing.T) {
	slow := Test{ID: "slow", Group: "g", Timeout: 50 * time.Millisecond, Run: func(ctx context.Context, l Lang) Result {
		time.Sleep(500 * time.Millisecond)
		return Result{Level: OK}
	}}
	start := time.Now()
	rep := Run(context.Background(), []Test{slow}, EN, nil)
	if time.Since(start) > 400*time.Millisecond || rep.Results[0].Level != Warn || !strings.Contains(rep.Results[0].Hint, "did not finish") {
		t.Fatalf("таймаут не сработал: %+v (%v)", rep.Results, time.Since(start))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rep := Run(ctx, []Test{slow, slow}, RU, nil); len(rep.Results) != 0 {
		t.Fatal("после отмены тесты не должны запускаться")
	}
}

func TestJudgeCPU(t *testing.T) {
	for _, c := range []struct {
		cores int
		aes   float64
		want  Level
	}{{4, 2000, OK}, {2, 450, OK}, {1, 2000, Warn}, {4, 300, Warn}, {4, 80, Bad}} {
		if got, _ := judgeCPU(c.cores, c.aes, RU); got != c.want {
			t.Errorf("%d ядер, %.0f МБ/с: %s, ожидалось %s", c.cores, c.aes, got, c.want)
		}
	}
}

func TestJudgeMemory(t *testing.T) {
	for _, c := range []struct {
		total, swap int
		want        Level
	}{{2048, 0, OK}, {1024, 0, OK}, {512, 0, Warn}, {512, 512, Warn}, {256, 1024, Bad}} {
		if got, _ := judgeMemory(c.total, c.swap, RU); got != c.want {
			t.Errorf("%d МБ, своп %d: %s, ожидалось %s", c.total, c.swap, got, c.want)
		}
	}
}

func TestJudgeDisk(t *testing.T) {
	for _, c := range []struct {
		mbps float64
		want Level
	}{{400, OK}, {60, OK}, {30, Warn}, {5, Bad}} {
		if got, _ := judgeDisk(c.mbps, EN); got != c.want {
			t.Errorf("%.0f МБ/с: %s, ожидалось %s", c.mbps, got, c.want)
		}
	}
}

func TestMeminfoParses(t *testing.T) {
	p := filepath.Join(t.TempDir(), "meminfo")
	_ = os.WriteFile(p, []byte("MemTotal:        2048000 kB\nMemFree: 1 kB\nMemAvailable:    1024000 kB\nSwapTotal:       524288 kB\nBad line\n"), 0o600)
	total, swap, avail, ok := meminfo(p)
	if !ok || total != 2000 || swap != 512 || avail != 1000 {
		t.Fatalf("%d %d %d %v", total, swap, avail, ok)
	}
	if _, _, _, ok := meminfo(filepath.Join(t.TempDir(), "нет")); ok {
		t.Fatal("несуществующий файл должен давать ok=false")
	}
}

func TestClassifyAddrs(t *testing.T) {
	mk := func(s string) net.Addr {
		_, n, _ := net.ParseCIDR(s)
		ip, _, _ := net.ParseCIDR(s)
		n.IP = ip
		return n
	}
	pub4, priv4, pub6 := classifyAddrs([]net.Addr{mk("203.0.113.5/24"), mk("10.0.0.4/24"), mk("100.64.1.2/10"), mk("2001:db8::1/64"), mk("fe80::1/64"), mk("fd00::1/64")})
	if pub4 != 1 || priv4 != 2 || pub6 != 1 {
		t.Fatalf("pub4=%d priv4=%d pub6=%d", pub4, priv4, pub6)
	}
}

// Настоящие локальные тесты: должны отработать быстро, без паники и с понятными полями.
func TestLocalRunsForReal(t *testing.T) {
	if testing.Short() {
		t.Skip("короткий режим")
	}
	rep := Run(context.Background(), Local(), EN, nil)
	if len(rep.Results) != 4 {
		t.Fatalf("результатов %d", len(rep.Results))
	}
	for _, r := range rep.Results {
		if r.Title == "" || r.Level == "" || r.Group == "" || r.ID == "" {
			t.Errorf("неполный результат: %+v", r)
		}
	}
	if rep.Results[0].ID != "cpu" || !strings.Contains(rep.Results[0].Detail, "AES-GCM") {
		t.Errorf("cpu: %+v", rep.Results[0])
	}
}
