//go:build linux

package awg

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

// defaultIface – интерфейс, через который сервер выходит в интернет.
func defaultIface() string {
	out, err := exec.Command("ip", "-o", "route", "get", "1.1.1.1").Output()
	if err != nil {
		return ""
	}
	f := strings.Fields(string(out))
	for i, v := range f {
		if v == "dev" && i+1 < len(f) {
			return f[i+1]
		}
	}
	return ""
}

// setupNetwork назначает адрес туннелю, включает пересылку пакетов и NAT. Возвращает функцию отката.
func setupNetwork(iface string, cfg Config) (func(), error) {
	if err := run("ip", "addr", "replace", cfg.Address, "dev", iface); err != nil {
		return nil, err
	}
	if err := run("ip", "link", "set", "dev", iface, "mtu", fmt.Sprint(cfg.MTU), "up"); err != nil {
		return nil, err
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		return nil, fmt.Errorf("не удалось включить ip_forward: %w", err)
	}
	_, subnet, err := net.ParseCIDR(cfg.Address)
	if err != nil {
		return nil, err
	}
	out := defaultIface()
	var undo []func()
	if out != "" {
		rule := []string{"-s", subnet.String(), "-o", out, "-j", "MASQUERADE"}
		if run("iptables", append([]string{"-t", "nat", "-C", "POSTROUTING"}, rule...)...) != nil {
			if err := run("iptables", append([]string{"-t", "nat", "-A", "POSTROUTING"}, rule...)...); err != nil {
				return nil, err
			}
			undo = append(undo, func() { _ = run("iptables", append([]string{"-t", "nat", "-D", "POSTROUTING"}, rule...)...) })
		}
		fwd := []string{"-i", iface, "-j", "ACCEPT"}
		if run("iptables", append([]string{"-C", "FORWARD"}, fwd...)...) != nil {
			if err := run("iptables", append([]string{"-I", "FORWARD", "1"}, fwd...)...); err == nil {
				undo = append(undo, func() { _ = run("iptables", append([]string{"-D", "FORWARD"}, fwd...)...) })
			}
		}
	}
	return func() {
		for _, u := range undo {
			u()
		}
		_ = run("ip", "link", "del", "dev", iface)
	}, nil
}
