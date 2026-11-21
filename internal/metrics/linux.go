package metrics

import (
	"os"
	"strconv"
	"strings"
)

func readLinux() (cpu float64, memUsed, memTotal uint64, uptime int64, load float64, rx, tx uint64, ok bool) {
	// CPU по /proc/stat между двумя замерами
	if b, err := os.ReadFile("/proc/stat"); err == nil {
		line := strings.SplitN(string(b), "\n", 2)[0]
		f := strings.Fields(line)
		if len(f) >= 5 && f[0] == "cpu" {
			var total, idle uint64
			for i, v := range f[1:] {
				n, _ := strconv.ParseUint(v, 10, 64)
				total += n
				if i == 3 || i == 4 { // idle + iowait
					idle += n
				}
			}
			if prevCPUTotal > 0 && total > prevCPUTotal {
				dt := float64(total - prevCPUTotal)
				di := float64(idle - prevCPUIdle)
				cpu = (dt - di) / dt * 100
			}
			prevCPUTotal, prevCPUIdle = total, idle
		}
	}
	// Память по /proc/meminfo
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, avail uint64
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) < 2 {
				continue
			}
			v, _ := strconv.ParseUint(f[1], 10, 64)
			switch f[0] {
			case "MemTotal:":
				total = v * 1024
			case "MemAvailable:":
				avail = v * 1024
			}
		}
		memTotal = total
		if total > avail {
			memUsed = total - avail
		}
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			v, _ := strconv.ParseFloat(f[0], 64)
			uptime = int64(v)
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			load, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	// Сеть: все интерфейсы, кроме lo, docker и виртуальных
	if b, err := os.ReadFile("/proc/net/dev"); err == nil {
		for _, l := range strings.Split(string(b), "\n")[2:] {
			name, rest, found := strings.Cut(l, ":")
			name = strings.TrimSpace(name)
			if !found || name == "lo" || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "br-") {
				continue
			}
			f := strings.Fields(rest)
			if len(f) >= 9 {
				r, _ := strconv.ParseUint(f[0], 10, 64)
				t, _ := strconv.ParseUint(f[8], 10, 64)
				rx += r
				tx += t
			}
		}
	}
	ok = memTotal > 0
	return
}
