// Package core управляет ядрами, которые обслуживают подключения (Xray, sing-box, mita, mtg…):
// ищет и устанавливает бинарники, собирает конфиги, запускает процессы и перезапускает их при сбое.
package core

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	BinDir = "bin"
	LogDir = "logs"
)

// Proc – процесс ядра под присмотром панели.
type Proc struct {
	Name string

	mu        sync.Mutex
	cmd       *exec.Cmd
	exited    chan struct{} // закрывается, когда процесс cmd завершился
	want      bool
	args      []string
	bin       string
	env       []string
	dir       string
	startedAt time.Time
	restarts  int
	lastErr   string
}

type Status struct {
	Name     string `json:"name"`
	Running  bool   `json:"running"`
	Binary   string `json:"binary"`
	PID      int    `json:"pid"`
	Uptime   int64  `json:"uptime_sec"`
	Restarts int    `json:"restarts"`
	LastErr  string `json:"last_error,omitempty"`
}

func NewProc(name string) *Proc { return &Proc{Name: name} }

// Start запускает процесс (или перезапускает с новыми параметрами).
func (p *Proc) Start(bin string, args []string, env []string, dir string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopLocked()
	p.bin, p.args, p.env, p.dir, p.want = bin, args, env, dir, true
	return p.spawnLocked()
}

func (p *Proc) pidFile() string { return filepath.Join("run", p.Name+".pid") }

// killStale убивает процесс, оставшийся от прошлого запуска панели (например, после сбоя): он держит порты.
func (p *Proc) killStale() {
	data, err := os.ReadFile(p.pidFile())
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return
	}
	// убеждаемся, что это наш бинарник, а не чужой процесс с тем же pid
	out, _ := exec.Command("ps", "-o", "comm=", "-p", strconv.Itoa(pid)).Output()
	if !strings.Contains(string(out), filepath.Base(p.bin)) {
		_ = os.Remove(p.pidFile())
		return
	}
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	_ = syscall.Kill(pid, syscall.SIGTERM)
	for i := 0; i < 30; i++ {
		if syscall.Kill(pid, 0) != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if syscall.Kill(pid, 0) == nil {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		time.Sleep(200 * time.Millisecond)
	}
	_ = os.Remove(p.pidFile())
}

func (p *Proc) spawnLocked() error {
	if err := os.MkdirAll(LogDir, 0o755); err != nil {
		return err
	}
	if p.cmd == nil {
		p.killStale()
	}
	logf, err := os.OpenFile(filepath.Join(LogDir, p.Name+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	cmd := exec.Command(p.bin, p.args...)
	cmd.Env = append(os.Environ(), p.env...)
	cmd.Dir = p.dir
	var w io.Writer = logf
	cmd.Stdout, cmd.Stderr = w, w
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		logf.Close()
		p.lastErr = err.Error()
		return fmt.Errorf("не удалось запустить %s: %w", p.Name, err)
	}
	exited := make(chan struct{})
	p.cmd, p.exited, p.startedAt, p.lastErr = cmd, exited, time.Now(), ""
	_ = os.MkdirAll("run", 0o755)
	_ = os.WriteFile(p.pidFile(), []byte(strconv.Itoa(cmd.Process.Pid)), 0o644)
	go p.watch(cmd, logf, exited)
	return nil
}

// watch ждёт завершения процесса и перезапускает его, если он нужен и упал сам.
func (p *Proc) watch(cmd *exec.Cmd, logf *os.File, exited chan struct{}) {
	err := cmd.Wait()
	logf.Close()
	close(exited)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != cmd {
		return // уже заменён новым запуском
	}
	p.cmd = nil
	if err != nil {
		p.lastErr = err.Error()
	}
	if !p.want {
		return
	}
	p.restarts++
	delay := 2 * time.Second
	if time.Since(p.startedAt) < 5*time.Second {
		delay = 10 * time.Second // падает сразу – не молотим
	}
	go func() {
		time.Sleep(delay)
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.want && p.cmd == nil {
			_ = p.spawnLocked()
		}
	}()
}

func (p *Proc) stopLocked() {
	cmd, exited := p.cmd, p.exited
	p.want = false
	p.cmd = nil
	if cmd == nil || cmd.Process == nil {
		return
	}
	defer os.Remove(p.pidFile())
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	// ждём настоящего завершения: новый запуск должен получить освободившиеся порты
	p.mu.Unlock()
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-exited:
		case <-time.After(2 * time.Second):
		}
	}
	p.mu.Lock()
}

func (p *Proc) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopLocked()
}

func (p *Proc) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cmd != nil
}

func (p *Proc) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := Status{Name: p.Name, Binary: p.bin, Restarts: p.restarts, LastErr: p.lastErr, Running: p.cmd != nil}
	if p.cmd != nil && p.cmd.Process != nil {
		st.PID = p.cmd.Process.Pid
		st.Uptime = int64(time.Since(p.startedAt).Seconds())
	}
	return st
}
