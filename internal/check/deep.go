package check

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/proto"
)

// Deep проверяет подключения так, как это делает клиент: настоящий клиент Xray заходит на сервер через каждое
// включённое подключение и открывает страницу. Проверка идёт с самого сервера: доступность из вашей сети она не покажет.
func Deep() Report {
	r := Report{}
	add := func(level, text string) {
		r.Items = append(r.Items, Item{Group: "Подключения клиентом", Level: level, Text: text})
		switch level {
		case Bad:
			r.Bad++
		case Warn:
			r.Warn++
		}
	}
	bin := core.XrayBinary()
	sbBin := core.SingboxBinary()
	if bin == "" && sbBin == "" {
		add(Warn, "Ядра не найдены – подключения клиентом не проверить")
		return r
	}
	if _, err := exec.LookPath("curl"); err != nil {
		add(Warn, "Нет curl – подключения клиентом не проверить")
		return r
	}
	users, _ := db.GetUsers()
	var user *db.User
	for i := range users {
		if users[i].Active() {
			user = &users[i]
			break
		}
	}
	if user == nil {
		add(Info, "Нет активных пользователей – проверять подключения нечем (создайте пользователя)")
		return r
	}
	env := core.PublicEnv()
	inbounds, _ := db.GetInbounds()

	type result struct {
		idx   int
		level string
		text  string
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := map[int]result{}
	port := 18080
	order := 0
	for _, ib := range inbounds {
		if !ib.Enable {
			continue
		}
		p, err := proto.NewProfile(ib, *user, env)
		if err != nil {
			continue
		}
		p.Host = "127.0.0.1" // подключаемся к самому серверу, SNI остаётся прежним
		var runner func(port int) (bool, string)
		switch {
		case p.XrayOutbound() != nil && bin != "" && core.XrayProc.Running():
			out := p.XrayOutbound()
			runner = func(port int) (bool, string) { return probe(bin, port, out) }
		case p.SingboxProbeOutbound(core.PublicEnv()) != nil && sbBin != "" && core.SingboxProc.Running():
			out := p.SingboxProbeOutbound(core.PublicEnv())
			runner = func(port int) (bool, string) { return probeSingbox(sbBin, port, out) }
		default:
			continue // этим клиентом не проверить: останется проверка порта
		}
		order++
		port++
		wg.Add(1)
		go func(idx, port int, name, title string, run func(int) (bool, string)) {
			defer wg.Done()
			ok, detail := run(port)
			if !ok { // ядро могло только что перезапуститься (применение настроек) – даём вторую попытку
				time.Sleep(3 * time.Second)
				ok, detail = run(port)
			}
			res := result{idx: idx, level: OK, text: fmt.Sprintf("%s: клиент подключился к серверу и открыл страницу", name)}
			if !ok {
				res.level = Bad
				res.text = fmt.Sprintf("[%s] %s: клиент не смог подключиться (%s)", CodeProtocolHandshake, name, detail)
			}
			mu.Lock()
			results[idx] = res
			mu.Unlock()
		}(order, port, p.Name, p.Kind.Title(), runner)
	}
	wg.Wait()
	for i := 1; i <= order; i++ {
		if res, ok := results[i]; ok {
			add(res.level, res.text)
		}
	}
	if order == 0 {
		add(Info, "Нет подключений Xray для проверки")
	} else {
		add(Info, "Проверка идёт с самого сервера: доступность из вашей сети она не покажет. Mieru, MTProto и AmneziaWG проверяются по порту.")
	}
	return r
}

// probe запускает клиент Xray с одним исходящим и ходит через него по SOCKS.
func probe(bin string, port int, outbound proto.M) (bool, string) {
	cfg := proto.M{
		"log":       proto.M{"loglevel": "none"},
		"inbounds":  []proto.M{{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": proto.M{"udp": false}}},
		"outbounds": []proto.M{outbound},
	}
	dir, err := os.MkdirTemp("", "kitsune-probe-*")
	if err != nil {
		return false, err.Error()
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "client.json")
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return false, err.Error()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "run", "-c", path)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(bin))
	if err := cmd.Start(); err != nil {
		return false, err.Error()
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	// ждём, пока клиент откроет локальный порт
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); err == nil {
			c.Close()
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	var last string
	for try := 0; try < 3; try++ {
		out, err := exec.Command("curl", "-fsS", "-m", "12", "--socks5-hostname", fmt.Sprintf("127.0.0.1:%d", port),
			"-o", "/dev/null", "https://www.cloudflare.com/cdn-cgi/trace").CombinedOutput()
		if err == nil {
			return true, ""
		}
		last = trimErr(string(out))
		time.Sleep(2 * time.Second)
	}
	return false, last
}

func trimErr(s string) string {
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// probeSingbox запускает клиент sing-box с одним исходящим и ходит через него по SOCKS.
func probeSingbox(bin string, port int, outbound proto.M) (bool, string) {
	cfg := proto.M{
		"log":       proto.M{"level": "error"},
		"inbounds":  []proto.M{{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": port}},
		"outbounds": []proto.M{outbound, {"type": "direct", "tag": "direct"}},
		"route":     proto.M{"rules": []proto.M{{"inbound": "in", "outbound": outbound["tag"]}}, "final": "direct"},
	}
	dir, err := os.MkdirTemp("", "kitsune-probe-*")
	if err != nil {
		return false, err.Error()
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "client.json")
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return false, err.Error()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "run", "-c", path)
	if err := cmd.Start(); err != nil {
		return false, err.Error()
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); err == nil {
			c.Close()
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	var last string
	for try := 0; try < 3; try++ {
		out, err := exec.Command("curl", "-fsS", "-m", "12", "--socks5-hostname", fmt.Sprintf("127.0.0.1:%d", port),
			"-o", "/dev/null", "https://www.cloudflare.com/cdn-cgi/trace").CombinedOutput()
		if err == nil {
			return true, ""
		}
		last = trimErr(string(out))
		time.Sleep(2 * time.Second)
	}
	return false, last
}
