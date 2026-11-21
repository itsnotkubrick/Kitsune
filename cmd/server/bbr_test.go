package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stubSysctl(t *testing.T, fail func(args []string) bool) *[]string {
	t.Helper()
	oldConf, oldGet, oldExec := bbrConf, sysctlGet, sysctlExec
	t.Cleanup(func() { bbrConf, sysctlGet, sysctlExec = oldConf, oldGet, oldExec })
	bbrConf = filepath.Join(t.TempDir(), "99-kitsune-bbr.conf")
	sysctlGet = func(key string) string {
		return map[string]string{"net.core.default_qdisc": "pfifo_fast", "net.ipv4.tcp_congestion_control": "cubic"}[key]
	}
	calls := []string{}
	sysctlExec = func(args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		if fail != nil && fail(args) {
			return errors.New("sysctl failed")
		}
		return nil
	}
	return &calls
}

func TestEnableBBRRollsBackOnError(t *testing.T) {
	calls := stubSysctl(t, func(a []string) bool { return a[0] == "-p" })
	if err := enableBBR(); err == nil {
		t.Fatal("ошибка sysctl должна вернуться")
	}
	if _, err := os.Stat(bbrConf); err == nil {
		t.Error("файл настройки должен быть удалён")
	}
	all := strings.Join(*calls, "|")
	if !strings.Contains(all, "net.core.default_qdisc=pfifo_fast") || !strings.Contains(all, "tcp_congestion_control=cubic") {
		t.Errorf("прежние значения не возвращены: %s", all)
	}
}

func TestEnableBBROk(t *testing.T) {
	stubSysctl(t, nil)
	if err := enableBBR(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(bbrConf); !strings.Contains(string(b), "bbr") {
		t.Error("файл не записан")
	}
}

func TestDisableBBRReportsSysctlError(t *testing.T) {
	stubSysctl(t, func(a []string) bool { return a[0] == "-w" })
	_ = os.WriteFile(bbrConf, []byte("x"), 0o644)
	if err := disableBBR(); err == nil {
		t.Error("ошибка sysctl должна вернуться")
	}
	if _, err := os.Stat(bbrConf); err == nil {
		t.Error("файл должен быть удалён")
	}
}
