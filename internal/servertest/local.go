package servertest

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Local – тесты без внешних запросов: процессор, диск, память, сетевые адреса самого сервера.
func Local() []Test {
	return []Test{
		{ID: "cpu", Group: "cpu", Timeout: 12 * time.Second, Run: testCPU},
		{ID: "memory", Group: "memory", Timeout: 3 * time.Second, Run: testMemory},
		{ID: "disk", Group: "disk", Timeout: 20 * time.Second, Run: testDisk},
		{ID: "addresses", Group: "network", Timeout: 3 * time.Second, Run: testAddresses},
	}
}

// ---- процессор ----

// Пороги оценки (МБ/с на одно ядро для AES-GCM): ниже – шифрование без аппаратной поддержки, Xray упрётся в процессор.
const (
	cpuWarnPerCoreMBps = 400
	cpuBadPerCoreMBps  = 120
)

// judgeCPU оценивает процессор по числу ядер и скорости AES-GCM на ядро.
func judgeCPU(cores int, aesPerCore float64, l Lang) (Level, string) {
	switch {
	case aesPerCore < cpuBadPerCoreMBps:
		return Bad, L(l, "Шифрование на этом процессоре очень медленное (нет аппаратного AES?). Для прокси на сотни Мбит/с нужен другой тариф или хостер.",
			"Encryption is very slow on this CPU (no hardware AES?). A different plan or host is needed for hundreds of Mbit/s.")
	case aesPerCore < cpuWarnPerCoreMBps:
		return Warn, L(l, "Шифрование медленнее обычного: скорость прокси упрётся в процессор раньше канала.",
			"Encryption is slower than usual: proxy speed will hit the CPU limit before the network.")
	case cores < 2:
		return Warn, L(l, "Одно ядро: при нескольких одновременных скачиваниях процессор станет узким местом.",
			"A single core: the CPU becomes the bottleneck with several simultaneous downloads.")
	}
	return OK, ""
}

func testCPU(ctx context.Context, l Lang) Result {
	cores := runtime.NumCPU()
	dur := 1500 * time.Millisecond
	aesTotal := cpuRate(ctx, cores, dur, aesWork)
	shaTotal := cpuRate(ctx, cores, dur/2, shaWork)
	perCore := aesTotal / float64(cores)
	lv, hint := judgeCPU(cores, perCore, l)
	return Result{ID: "cpu", Group: "cpu", Level: lv,
		Title:  L(l, "Процессор", "CPU"),
		Detail: fmt.Sprintf("%d %s, AES-GCM %.0f %s (%.0f %s %s), SHA-256 %.0f %s", cores, L(l, "ядер", "cores"), aesTotal, L(l, "МБ/с", "MB/s"), perCore, L(l, "МБ/с", "MB/s"), L(l, "на ядро", "per core"), shaTotal, L(l, "МБ/с", "MB/s")),
		Hint:   hint}
}

func aesWork() func() int {
	key := make([]byte, 32)
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	buf := make([]byte, 16<<10)
	nonce := make([]byte, g.NonceSize())
	out := make([]byte, 0, len(buf)+g.Overhead())
	return func() int { out = g.Seal(out[:0], nonce, buf, nil); return len(buf) }
}

func shaWork() func() int {
	buf := make([]byte, 64<<10)
	return func() int { sha256.Sum256(buf); return len(buf) }
}

// cpuRate гоняет работу на всех ядрах и возвращает суммарную скорость в МБ/с. У каждого потока свой экземпляр работы (общих буферов нет).
func cpuRate(ctx context.Context, threads int, d time.Duration, mk func() func() int) float64 {
	var total atomic.Int64
	var wg sync.WaitGroup
	end := time.Now().Add(d)
	start := time.Now()
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := mk()
			var n int64
			for time.Now().Before(end) && ctx.Err() == nil {
				for j := 0; j < 32; j++ {
					n += int64(w())
				}
			}
			total.Add(n)
		}()
	}
	wg.Wait()
	el := time.Since(start).Seconds()
	if el <= 0 {
		return 0
	}
	return float64(total.Load()) / (1 << 20) / el
}

// ---- память ----

const (
	memBadMB  = 350
	memWarnMB = 700
)

// judgeMemory оценивает память (в МБ) вместе со свопом.
func judgeMemory(totalMB, swapMB int, l Lang) (Level, string) {
	switch {
	case totalMB < memBadMB:
		return Bad, L(l, "Памяти очень мало: панель, ядро и система не поместятся без вылетов.", "Very little memory: the panel, the core and the system will not fit without crashes.")
	case totalMB < memWarnMB && swapMB == 0:
		return Warn, L(l, "Памяти немного и нет файла подкачки: при нескольких ядрах процессы могут вылетать.", "Little memory and no swap: processes may crash with several cores.")
	case totalMB < memWarnMB:
		return Warn, L(l, "Памяти немного: следите за нагрузкой при нескольких ядрах и протоколах.", "Little memory: watch the load with several cores and protocols.")
	}
	return OK, ""
}

// meminfo читает /proc/meminfo: всего памяти, своп, доступно (в МБ). ok=false, если файла нет (не Linux).
func meminfo(path string) (total, swap, avail int, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) < 2 {
			continue
		}
		kb, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		switch strings.TrimSuffix(parts[0], ":") {
		case "MemTotal":
			total = kb / 1024
		case "SwapTotal":
			swap = kb / 1024
		case "MemAvailable":
			avail = kb / 1024
		}
	}
	return total, swap, avail, total > 0
}

func testMemory(ctx context.Context, l Lang) Result {
	total, swap, avail, ok := meminfo("/proc/meminfo")
	if !ok {
		return Result{ID: "memory", Group: "memory", Level: Skip, Title: L(l, "Память", "Memory"), Detail: runtime.GOOS,
			Hint: L(l, "Проверка памяти доступна только на Linux.", "The memory check works on Linux only.")}
	}
	lv, hint := judgeMemory(total, swap, l)
	return Result{ID: "memory", Group: "memory", Level: lv, Title: L(l, "Память", "Memory"),
		Detail: fmt.Sprintf("%d %s, %s %d %s, %s %d %s", total, L(l, "МБ", "MB"), L(l, "своп", "swap"), swap, L(l, "МБ", "MB"), L(l, "доступно", "available"), avail, L(l, "МБ", "MB")), Hint: hint}
}

// ---- диск ----

const (
	diskBadMBps  = 15
	diskWarnMBps = 50
)

// judgeDisk оценивает скорость записи с принудительной синхронизацией (МБ/с).
func judgeDisk(writeMBps float64, l Lang) (Level, string) {
	switch {
	case writeMBps < diskBadMBps:
		return Bad, L(l, "Диск очень медленный: база и журналы будут тормозить панель.", "The disk is very slow: the database and logs will slow the panel down.")
	case writeMBps < diskWarnMBps:
		return Warn, L(l, "Диск медленнее обычного. Для прокси это терпимо, но резервные копии и обновления будут долгими.", "The disk is slower than usual. Fine for a proxy, but backups and updates will be slow.")
	}
	return OK, ""
}

func testDisk(ctx context.Context, l Lang) Result {
	const chunk, count = 1 << 20, 32
	title := L(l, "Диск", "Disk")
	f, err := os.CreateTemp("", "kitsune-disk-*")
	if err != nil {
		return Result{ID: "disk", Group: "disk", Level: Warn, Title: title, Detail: err.Error(), Hint: L(l, "Не удалось создать временный файл для проверки.", "Could not create a temporary file for the check.")}
	}
	defer os.Remove(f.Name())
	defer f.Close()
	buf := make([]byte, chunk)
	for i := range buf {
		buf[i] = byte(i*131 + 7) // не нули: на сжимающих дисках нули дали бы завышенную скорость
	}
	start := time.Now()
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		if _, err := f.Write(buf); err != nil {
			return Result{ID: "disk", Group: "disk", Level: Bad, Title: title, Detail: err.Error(), Hint: L(l, "Запись на диск не удалась (нет места?).", "Writing to disk failed (no space?).")}
		}
	}
	_ = f.Sync()
	el := time.Since(start).Seconds()
	if el <= 0 {
		el = 0.001
	}
	mbps := float64(count) / el
	lv, hint := judgeDisk(mbps, l)
	return Result{ID: "disk", Group: "disk", Level: lv, Title: title, Detail: fmt.Sprintf("%s %.0f %s (%d %s, fsync)", L(l, "запись", "write"), mbps, L(l, "МБ/с", "MB/s"), count, L(l, "МБ", "MB")), Hint: hint}
}

// ---- адреса ----

func isPrivate(ip net.IP) bool {
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1]&0xC0 == 64 // 100.64.0.0/10 (общий NAT провайдера)
}

// classifyAddrs разбирает адреса интерфейсов: есть ли публичные IPv4 и IPv6.
func classifyAddrs(addrs []net.Addr) (pub4, priv4, pub6 int) {
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := n.IP
		if ip.To4() != nil {
			if isPrivate(ip) {
				priv4++
			} else {
				pub4++
			}
		} else if ip.To16() != nil && !isPrivate(ip) {
			pub6++
		}
	}
	return
}

func testAddresses(ctx context.Context, l Lang) Result {
	title := L(l, "Сетевые адреса", "Network addresses")
	ifs, err := net.Interfaces()
	if err != nil {
		return Result{ID: "addresses", Group: "network", Level: Skip, Title: title, Detail: err.Error()}
	}
	var all []net.Addr
	mtu := 0
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if a, err := ifc.Addrs(); err == nil {
			all = append(all, a...)
			if mtu == 0 {
				mtu = ifc.MTU
			}
		}
	}
	pub4, priv4, pub6 := classifyAddrs(all)
	detail := fmt.Sprintf("IPv4 %s, IPv6 %s", yesNo(pub4 > 0, priv4 > 0, l), L(l, map[bool]string{true: "есть", false: "нет"}[pub6 > 0], map[bool]string{true: "yes", false: "no"}[pub6 > 0]))
	if mtu > 0 {
		detail += fmt.Sprintf(", MTU %d", mtu)
	}
	lv, hint := Info, ""
	if pub4 == 0 && priv4 > 0 {
		hint = L(l, "На интерфейсе только частный IPv4: сервер за NAT хостера. Публичный адрес и открытые порты проверяются внешним тестом.", "Only a private IPv4 on the interface: the server is behind the host's NAT. The public address and open ports are checked by an external test.")
	}
	if pub4 == 0 && priv4 == 0 {
		lv, hint = Warn, L(l, "IPv4-адресов не найдено: подключиться к серверу будет нельзя.", "No IPv4 addresses found: clients will not be able to connect.")
	}
	return Result{ID: "addresses", Group: "network", Level: lv, Title: title, Detail: detail, Hint: hint}
}

func yesNo(pub, priv bool, l Lang) string {
	switch {
	case pub:
		return L(l, "публичный", "public")
	case priv:
		return L(l, "только частный (NAT)", "private only (NAT)")
	}
	return L(l, "нет", "none")
}
