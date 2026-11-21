// Package metrics собирает показатели сервера для графиков дашборда: CPU, память, сеть, диск, нагрузка.
// На Linux данные берутся из /proc, на macOS (локальная разработка) – из системных утилит.
package metrics

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	interval   = 5 * time.Second
	maxSamples = 360 // 30 минут истории
)

type Sample struct {
	T     int64   `json:"t"`      // unix, сек
	CPU   float64 `json:"cpu"`    // %
	Mem   float64 `json:"mem"`    // %
	RxBps float64 `json:"rx_bps"` // байт/с
	TxBps float64 `json:"tx_bps"`
}

type Snapshot struct {
	CPU       float64 `json:"cpu"`
	CPUs      int     `json:"cpus"`
	MemUsed   uint64  `json:"mem_used"`
	MemTotal  uint64  `json:"mem_total"`
	DiskUsed  uint64  `json:"disk_used"`
	DiskTotal uint64  `json:"disk_total"`
	Load1     float64 `json:"load1"`
	UptimeSec int64   `json:"uptime_sec"`
	RxBps     float64 `json:"rx_bps"`
	TxBps     float64 `json:"tx_bps"`
	RxTotal   uint64  `json:"rx_total"`
	TxTotal   uint64  `json:"tx_total"`
	Hostname  string  `json:"os"`
	Available bool    `json:"available"`
	SampledAt int64   `json:"sampled_at"`
}

var (
	mu      sync.RWMutex
	history []Sample
	current Snapshot

	prevCPUIdle, prevCPUTotal uint64
	prevRx, prevTx            uint64
	prevAt                    time.Time
)

// Start запускает фоновый сбор. Первый замер делается сразу.
func Start() {
	go func() {
		collect()
		t := time.NewTicker(interval)
		for range t.C {
			collect()
		}
	}()
}

func Get() (Snapshot, []Sample) {
	mu.RLock()
	defer mu.RUnlock()
	h := make([]Sample, len(history))
	copy(h, history)
	return current, h
}

func collect() {
	now := time.Now()
	snap := Snapshot{CPUs: runtime.NumCPU(), Hostname: runtime.GOOS, SampledAt: now.Unix()}

	cpu, memUsed, memTotal, up, load, rx, tx, ok := read()
	snap.Available = ok
	snap.MemUsed, snap.MemTotal, snap.UptimeSec, snap.Load1 = memUsed, memTotal, up, load
	snap.RxTotal, snap.TxTotal = rx, tx
	snap.DiskUsed, snap.DiskTotal = disk()

	mu.Lock()
	defer mu.Unlock()
	snap.CPU = cpu
	if !prevAt.IsZero() && rx >= prevRx && tx >= prevTx {
		dt := now.Sub(prevAt).Seconds()
		if dt > 0 {
			snap.RxBps = float64(rx-prevRx) / dt
			snap.TxBps = float64(tx-prevTx) / dt
		}
	}
	prevRx, prevTx, prevAt = rx, tx, now
	current = snap

	memPct := 0.0
	if memTotal > 0 {
		memPct = float64(memUsed) / float64(memTotal) * 100
	}
	history = append(history, Sample{T: now.Unix(), CPU: round1(cpu), Mem: round1(memPct), RxBps: snap.RxBps, TxBps: snap.TxBps})
	if len(history) > maxSamples {
		history = history[len(history)-maxSamples:]
	}
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }

func disk() (used, total uint64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return 0, 0
	}
	total = st.Blocks * uint64(st.Bsize)
	used = total - st.Bavail*uint64(st.Bsize)
	return
}

// read возвращает показатели ОС; вызывается под собственной синхронизацией только из collect.
func read() (cpu float64, memUsed, memTotal uint64, uptime int64, load float64, rx, tx uint64, ok bool) {
	if runtime.GOOS == "linux" {
		return readLinux()
	}
	if runtime.GOOS == "darwin" {
		return readDarwin()
	}
	return
}

func sh(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func readDarwin() (cpu float64, memUsed, memTotal uint64, uptime int64, load float64, rx, tx uint64, ok bool) {
	// CPU: сумма %CPU процессов / число ядер
	if out := sh("ps", "-A", "-o", "%cpu="); out != "" {
		var sum float64
		for _, l := range strings.Fields(out) {
			if v, err := strconv.ParseFloat(l, 64); err == nil {
				sum += v
			}
		}
		cpu = sum / float64(runtime.NumCPU())
		if cpu > 100 {
			cpu = 100
		}
	}
	// Память: hw.memsize и страницы из vm_stat
	if v, err := strconv.ParseUint(sh("sysctl", "-n", "hw.memsize"), 10, 64); err == nil {
		memTotal = v
	}
	vm := sh("vm_stat")
	page := uint64(16384)
	if i := strings.Index(vm, "page size of "); i >= 0 {
		f := strings.Fields(vm[i+len("page size of "):])
		if len(f) > 0 {
			if v, err := strconv.ParseUint(f[0], 10, 64); err == nil {
				page = v
			}
		}
	}
	pages := func(label string) uint64 {
		for _, l := range strings.Split(vm, "\n") {
			if strings.HasPrefix(l, label) {
				f := strings.Fields(strings.TrimSuffix(strings.TrimSpace(l[len(label):]), "."))
				if len(f) > 0 {
					v, _ := strconv.ParseUint(strings.TrimSuffix(f[0], "."), 10, 64)
					return v
				}
			}
		}
		return 0
	}
	used := pages("Pages active:") + pages("Pages wired down:") + pages("Pages occupied by compressor:")
	memUsed = used * page
	// Uptime: kern.boottime = { sec = 1234, usec = 0 } ...
	if bt := sh("sysctl", "-n", "kern.boottime"); bt != "" {
		if i := strings.Index(bt, "sec = "); i >= 0 {
			f := strings.FieldsFunc(bt[i+6:], func(r rune) bool { return r == ',' || r == ' ' })
			if len(f) > 0 {
				if s, err := strconv.ParseInt(f[0], 10, 64); err == nil {
					uptime = time.Now().Unix() - s
				}
			}
		}
	}
	// Load: { 1.23 1.10 1.05 }
	if la := strings.Trim(sh("sysctl", "-n", "vm.loadavg"), "{} "); la != "" {
		if f := strings.Fields(la); len(f) > 0 {
			load, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	// Сеть: суммарно по интерфейсам с адресом (netstat -ib), без lo0
	seen := map[string]bool{}
	for i, l := range strings.Split(sh("netstat", "-ib"), "\n") {
		f := strings.Fields(l)
		if i == 0 || len(f) < 10 || strings.HasPrefix(f[0], "lo") || seen[f[0]] || !strings.HasPrefix(f[2], "<Link") {
			continue
		}
		seen[f[0]] = true
		// Колонки: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes
		n := len(f)
		if v, err := strconv.ParseUint(f[n-5], 10, 64); err == nil {
			rx += v
		}
		if v, err := strconv.ParseUint(f[n-2], 10, 64); err == nil {
			tx += v
		}
	}
	ok = memTotal > 0
	return
}
