package bridge

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// Состояние узла по проверке с сервера. Проверяются только TCP-порты: UDP с сервера проверить нечем, такой узел остаётся «неизвестным».
// Проверка с сервера показывает, что узел жив и порт на нём открыт, но не заменяет замер из сети клиента.

const failsToDown = 3 // неудач подряд, после которых узел считается упавшим

// Status – последнее известное состояние узла.
type Status struct {
	State       string       `json:"state"`             // ok | down | unknown
	Ms          int64        `json:"ms,omitempty"`      // время TCP-соединения лучшего порта
	Since       int64        `json:"since,omitempty"`   // с какого момента состояние (unix)
	Checked     int64        `json:"checked,omitempty"` // когда проверяли в последний раз (unix)
	Fingerprint string       `json:"config_fingerprint,omitempty"`
	ProbeKind   string       `json:"probe_kind"`
	Ports       []PortStatus `json:"ports,omitempty"`
	LastSuccess int64        `json:"last_success,omitempty"`
	successes   int
	fails       int
}

var (
	stMu     sync.Mutex
	statuses = map[string]Status{}
)

// StatusOf возвращает состояние узла (unknown, если его ещё не проверяли).
func StatusOf(id string) Status {
	stMu.Lock()
	defer stMu.Unlock()
	if s, ok := statuses[id]; ok {
		return s
	}
	return Status{State: "unknown", ProbeKind: "tcp_connect"}
}

// Down: узел считается упавшим (три проверки подряд без ответа).
func Down(id string) bool { return StatusOf(id).State == "down" }

// Observe записывает результат проверки. known=false – проверить нечем (нет TCP-портов). Возвращает новое состояние и признак смены.
func Observe(id string, known, ok bool, ms int64, now time.Time) (Status, bool) {
	stMu.Lock()
	defer stMu.Unlock()
	old, had := statuses[id]
	st := old
	st.Checked = now.Unix()
	st.ProbeKind = "tcp_connect"
	switch {
	case !known:
		st = Status{State: "unknown", Checked: st.Checked, Since: st.Since, ProbeKind: "tcp_connect", LastSuccess: st.LastSuccess}
		if old.State != "unknown" || !had {
			st.Since = now.Unix()
		}
	case ok:
		st.fails, st.Ms = 0, ms
		st.LastSuccess = now.Unix()
		st.successes++
		if old.State == "down" && st.successes < 2 {
			break
		}
		if old.State != "ok" {
			st.State, st.Since = "ok", now.Unix()
		}
	default:
		st.successes = 0
		st.fails++
		st.Ms = 0
		if st.fails >= failsToDown && old.State != "down" {
			st.State, st.Since = "down", now.Unix()
		} else if !had || old.State == "unknown" {
			st.State = "unknown"
		}
	}
	statuses[id] = st
	return st, st.State != old.State
}

// dialTCP – проверка порта; в тестах подменяется.
var dialTCP = func(addr string, to time.Duration) (time.Duration, error) {
	t := time.Now()
	c, err := net.DialTimeout("tcp", addr, to)
	if err != nil {
		return 0, err
	}
	_ = c.Close()
	return time.Since(t), nil
}

// ProbeTCP проверяет TCP-порты узла. known=false, если TCP-портов нет. ok – отвечает хотя бы один порт; ms – лучшее время.
func ProbeTCP(addr string, fw []Forward) (known, ok bool, ms int64) {
	for _, f := range fw {
		if f.Proto != "tcp" {
			continue
		}
		known = true
		d, err := dialTCP(net.JoinHostPort(addr, strconv.Itoa(f.Port)), 5*time.Second)
		if err != nil {
			continue
		}
		if m := d.Milliseconds(); !ok || m < ms {
			ms = m
		}
		ok = true
	}
	return known, ok, ms
}

// Status identity includes configuration; old failure must not hide a changed node.
func fingerprint(n Node) string {
	b, _ := json.Marshal(n)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
func StatusOfNode(n Node) Status {
	st := StatusOf(n.ID)
	if st.Fingerprint != "" && st.Fingerprint != fingerprint(n) {
		return Status{State: "unknown", ProbeKind: "tcp_connect"}
	}
	if st.Checked != 0 && time.Now().Unix()-st.Checked > 300 {
		return Status{State: "unknown", ProbeKind: "tcp_connect"}
	}
	return st
}
func DownNode(n Node) bool { return StatusOfNode(n).State == "down" }
func ObserveNode(n Node, known, ok bool, ms int64, now time.Time, ports ...[]PortStatus) (Status, bool) {
	fp := fingerprint(n)
	stMu.Lock()
	if old, has := statuses[n.ID]; has && old.Fingerprint != fp {
		delete(statuses, n.ID)
	}
	stMu.Unlock()
	st, changed := Observe(n.ID, known, ok, ms, now)
	stMu.Lock()
	st.Fingerprint = fp
	if len(ports) > 0 {
		old := statuses[n.ID].Ports
		st.Ports = append([]PortStatus(nil), ports[0]...)
		for i := range st.Ports {
			p := &st.Ports[i]
			p.Checked = now.Unix()
			p.State = "unknown"
			for _, o := range old {
				if o.Proto == p.Proto && o.Port == p.Port {
					p.fails = o.fails
					p.successes = o.successes
					p.State = o.State
					p.LastSuccess = o.LastSuccess
					break
				}
			}
			if p.Proto != "tcp" {
				continue
			}
			if p.OK {
				p.fails = 0
				p.successes++
				p.LastSuccess = now.Unix()
				if p.State != "down" || p.successes >= 2 {
					p.State = "ok"
				}
			} else {
				p.successes = 0
				p.fails++
				if p.fails >= failsToDown {
					p.State = "down"
				}
			}
		}
	}
	statuses[n.ID] = st
	stMu.Unlock()
	return st, changed
}

type PortStatus struct {
	Proto       string `json:"proto"`
	Port        int    `json:"port"`
	OK          bool   `json:"ok"`
	Ms          int64  `json:"ms,omitempty"`
	Note        string `json:"note,omitempty"`
	Error       string `json:"error,omitempty"`
	State       string `json:"state"`
	Checked     int64  `json:"checked,omitempty"`
	LastSuccess int64  `json:"last_success,omitempty"`
	fails       int
	successes   int
}

func ProbePorts(ctx context.Context, addr string, fw []Forward) []PortStatus {
	out := make([]PortStatus, 0, len(fw))
	for _, f := range fw {
		r := PortStatus{Proto: f.Proto, Port: f.Port}
		if f.Proto != "tcp" {
			r.Note = "UDP: требуется клиентская проверка"
			out = append(out, r)
			continue
		}
		start := time.Now()
		d := net.Dialer{Timeout: 5 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(f.Port)))
		if err != nil {
			r.Note = "TCP-соединение не установлено"
			r.Error = "unreachable"
			var ne net.Error
			switch {
			case errors.Is(err, context.Canceled):
				r.Error = "cancelled"
			case errors.Is(err, context.DeadlineExceeded):
				r.Error = "timeout"
			case errors.Is(err, syscall.ECONNREFUSED):
				r.Error = "refused"
			case errors.As(err, &ne) && ne.Timeout():
				r.Error = "timeout"
			}
		} else {
			conn.Close()
			r.OK = true
			r.Ms = time.Since(start).Milliseconds()
		}
		out = append(out, r)
	}
	return out
}

func PruneStatuses(nodes []Node) {
	keep := map[string]bool{}
	for _, n := range nodes {
		keep[n.ID] = true
	}
	stMu.Lock()
	defer stMu.Unlock()
	for id := range statuses {
		if !keep[id] {
			delete(statuses, id)
		}
	}
}

// ProfileDown uses evidence for this TCP port; another failing port cannot hide it.
func ProfileDown(n Node, port int) bool {
	st := StatusOfNode(n)
	if st.State == "unknown" {
		return false
	}
	for _, p := range st.Ports {
		if p.Proto == "tcp" && p.Port == port {
			return p.State == "down"
		}
	}
	// Compatibility for direct Observe callers; production always records a fingerprint.
	return st.Fingerprint == "" && st.State == "down"
}
