package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"kitsune/internal/db"
	"kitsune/internal/events"
)

// Лимит устройств: сколько разных IP-адресов может одновременно пользоваться одним аккаунтом.
// Xray сам ведёт список «онлайн» адресов пользователя (statsUserOnline); панель раз в несколько секунд читает его
// и закрывает для лишних адресов новые соединения командой sib. Работает для протоколов Xray.
//
// Ограничения: уже открытые соединения лишнего адреса доживают до закрытия; адрес 127.0.0.1 Xray как онлайн не считает.

const (
	blockTTL     = 10 * time.Minute // на сколько закрывается лишний адрес
	onlineWindow = 90 * time.Second // адрес считается активным, если виден позже этого срока
)

type OnlineIP struct {
	IP       string `json:"ip"`
	LastSeen int64  `json:"lastSeen"`
}

type onlineUser struct {
	Email string     `json:"email"`
	IPs   []OnlineIP `json:"ips"`
}

// parseOnline разбирает ответ `xray api statsonlineiplist -all`.
func parseOnline(data []byte) (map[string][]OnlineIP, error) {
	var resp struct {
		Users []onlineUser `json:"users"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	out := map[string][]OnlineIP{}
	for _, u := range resp.Users {
		for i := range u.IPs { // Xray пишет IPv6 в квадратных скобках
			u.IPs[i].IP = strings.Trim(u.IPs[i].IP, "[]")
		}
		out[u.Email] = u.IPs
	}
	return out, nil
}

func queryOnline() (map[string][]OnlineIP, error) {
	bin := XrayBinary()
	if bin == "" || !XrayProc.Running() {
		return nil, fmt.Errorf("ядро не запущено")
	}
	cmd := exec.Command(bin, "api", "statsonlineiplist", "--server=127.0.0.1:10085", "-all")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return parseOnline(out.Bytes())
}

// DeviceDecision – что решено по одному пользователю.
type DeviceDecision struct {
	Allowed []string
	Extra   []string
}

// decideDevices выбирает, каким адресам разрешено пользоваться аккаунтом: первым по времени появления, остальным – блок.
func decideDevices(limit int, online []string, first map[string]time.Time) DeviceDecision {
	sort.SliceStable(online, func(i, j int) bool {
		fi, fj := first[online[i]], first[online[j]]
		if fi.Equal(fj) {
			return online[i] < online[j]
		}
		return fi.Before(fj)
	})
	if limit <= 0 || len(online) <= limit {
		return DeviceDecision{Allowed: online}
	}
	return DeviceDecision{Allowed: online[:limit], Extra: online[limit:]}
}

type deviceState struct {
	mu        sync.Mutex
	firstSeen map[int]map[string]time.Time    // userID -> ip -> когда появился
	blocked   map[string]map[string]time.Time // тег подключения -> ip -> до какого времени закрыт
	applied   map[string]string               // тег -> применённый набор (для сравнения)
	pid       int
}

var devices = &deviceState{firstSeen: map[int]map[string]time.Time{}, blocked: map[string]map[string]time.Time{}, applied: map[string]string{}}

func ruleTag(tag string) string { return "kitsune-sib-" + tag }

func sib(tag string, ips []string) error {
	bin := XrayBinary()
	rt := ruleTag(tag)
	if len(ips) == 0 {
		return exec.Command(bin, "api", "rmrules", "--server=127.0.0.1:10085", rt).Run()
	}
	args := append([]string{"api", "sib", "--server=127.0.0.1:10085", "-outbound=blocked", "-inbound=" + tag, "-ruletag=" + rt, "-reset"}, ips...)
	return exec.Command(bin, args...).Run()
}

// EnforceDeviceLimits – один проход проверки. Вызывается монитором раз в несколько секунд.
func EnforceDeviceLimits() {
	users, err := db.GetUsers()
	if err != nil {
		return
	}
	limited := map[int]db.User{}
	for _, u := range users {
		if u.IPLimit > 0 && u.Active() {
			limited[u.ID] = u
		}
	}
	devices.mu.Lock()
	defer devices.mu.Unlock()

	// После перезапуска Xray правила блокировки исчезли – начинаем заново.
	if pid := XrayProc.Status().PID; pid != devices.pid {
		devices.pid = pid
		devices.blocked = map[string]map[string]time.Time{}
		devices.applied = map[string]string{}
	}
	if len(limited) == 0 && len(devices.blocked) == 0 {
		return
	}
	online, err := queryOnline()
	if err != nil {
		return
	}
	now := time.Now()

	// email -> пользователь и тег подключения
	owner := map[string]struct {
		user db.User
		tag  string
	}{}
	for _, u := range limited {
		inbounds, _ := db.GetInbounds()
		for _, ib := range inbounds {
			owner[db.ClientEmail(u.Name, ib.Tag)] = struct {
				user db.User
				tag  string
			}{u, ib.Tag}
		}
	}

	for uid, u := range limited {
		active := map[string]bool{}
		for email, ips := range online {
			o, ok := owner[email]
			if !ok || o.user.ID != uid {
				continue
			}
			for _, ip := range ips {
				if time.Since(time.Unix(ip.LastSeen, 0)) <= onlineWindow {
					active[ip.IP] = true
				}
			}
		}
		fs := devices.firstSeen[uid]
		if fs == nil {
			fs = map[string]time.Time{}
			devices.firstSeen[uid] = fs
		}
		var list []string
		for ip := range active {
			if _, ok := fs[ip]; !ok {
				fs[ip] = now
			}
			list = append(list, ip)
		}
		for ip := range fs { // забываем адреса, которых давно нет
			if !active[ip] && now.Sub(fs[ip]) > time.Hour {
				delete(fs, ip)
			}
		}
		dec := decideDevices(u.IPLimit, list, fs)
		for _, ip := range dec.Extra {
			for email, o := range owner {
				if o.user.ID != uid {
					continue
				}
				m := devices.blocked[o.tag]
				if m == nil {
					m = map[string]time.Time{}
					devices.blocked[o.tag] = m
				}
				if _, already := m[ip]; !already {
					events.Notify("device_limit", fmt.Sprintf("%d|%s", uid, ip),
						fmt.Sprintf("пользователь %s: превышен лимит устройств (%d), адрес %s закрыт на %d мин.", u.Name, u.IPLimit, ip, int(blockTTL.Minutes())), 30*time.Minute)
				}
				m[ip] = now.Add(blockTTL)
				_ = email
			}
		}
	}

	// снимаем истёкшие блоки и применяем изменения
	for tag, m := range devices.blocked {
		for ip, until := range m {
			if now.After(until) {
				delete(m, ip)
			}
		}
		var ips []string
		for ip := range m {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		sig := strings.Join(ips, ",")
		if devices.applied[tag] != sig {
			if err := sib(tag, ips); err == nil {
				devices.applied[tag] = sig
			}
		}
		if len(m) == 0 {
			delete(devices.blocked, tag)
		}
	}
}

// BlockedIPs – текущие закрытые адреса (для интерфейса и проверок).
func BlockedIPs() map[string][]string {
	devices.mu.Lock()
	defer devices.mu.Unlock()
	out := map[string][]string{}
	for tag, m := range devices.blocked {
		for ip := range m {
			out[tag] = append(out[tag], ip)
		}
	}
	return out
}
