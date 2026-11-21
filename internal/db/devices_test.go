package db

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	_ "modernc.org/sqlite"
)

func TestDeviceLimit(t *testing.T) {
	var err error
	DB, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	DB.SetMaxOpenConns(1)
	initDevices()
	ok := func(hw string, limit int) bool {
		r, err := TouchDevice(1, Device{HWID: hw}, limit)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if !ok("a", 2) || !ok("b", 2) {
		t.Fatal("первые два устройства должны проходить")
	}
	if ok("c", 2) {
		t.Fatal("третье устройство должно упереться в лимит")
	}
	if !ok("a", 2) {
		t.Fatal("известное устройство должно проходить всегда")
	}
	if !ok("c", 0) {
		t.Fatal("без лимита проходят все")
	}
	l0, _ := ListDevices(1)
	_ = DeleteDevice(1, l0[0].ID)
	if l, _ := ListDevices(1); len(l) != 2 {
		t.Fatalf("после удаления должно остаться 2 устройства, осталось %d", len(l))
	}
	if CleanHeader("ab\x00cтй", 10) != "abc" {
		t.Fatal("в заголовке остаются только печатные ASCII")
	}
}

func openDevicesDB(t *testing.T) {
	t.Helper()
	var err error
	DB, err = sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "d.db")+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = DB.Close() })
	initDevices()
}

func TestDeviceLimitParallel(t *testing.T) {
	openDevicesDB(t)
	for round := 0; round < 5; round++ {
		uid := round + 1
		var wg sync.WaitGroup
		for i := 0; i < 64; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, _ = TouchDevice(uid, Device{HWID: fmt.Sprintf("dev-%d", i)}, 2)
			}(i)
		}
		wg.Wait()
		if l, _ := ListDevices(uid); len(l) != 2 {
			t.Fatalf("раунд %d: при лимите 2 записано устройств: %d", round, len(l))
		}
	}
}

func TestDeviceCeiling(t *testing.T) {
	openDevicesDB(t)
	for i := 0; i < MaxUserDevices+30; i++ {
		if ok, err := TouchDevice(1, Device{HWID: fmt.Sprintf("d%d", i)}, 0); !ok || err != nil {
			t.Fatalf("без лимита устройство %d должно приниматься: %v", i, err)
		}
	}
	l, _ := ListDevices(1)
	if len(l) != MaxUserDevices {
		t.Fatalf("потолок %d, записано %d", MaxUserDevices, len(l))
	}
	last := false
	for _, d := range l {
		if d.HWID == fmt.Sprintf("d%d", MaxUserDevices+29) {
			last = true
		}
		if d.HWID == "d0" {
			t.Fatal("самое давнее устройство должно вытесниться")
		}
	}
	if !last {
		t.Fatal("новейшее устройство должно остаться")
	}
	if ok, _ := TouchDevice(2, Device{HWID: "x"}, 1000); !ok {
		t.Fatal("большой лимит не должен блокировать первое устройство")
	}
}

func TestDeviceKeepsFieldsAndCase(t *testing.T) {
	openDevicesDB(t)
	_, _ = TouchDevice(1, Device{HWID: "DEV-A", OS: "iOS", OSVersion: "17", Model: "iPhone"}, 1)
	if ok, _ := TouchDevice(1, Device{HWID: "dev-a"}, 1); !ok {
		t.Fatal("тот же HWID в другом регистре – то же устройство")
	}
	l, _ := ListDevices(1)
	if len(l) != 1 || l[0].OS != "iOS" || l[0].OSVersion != "17" || l[0].Model != "iPhone" {
		t.Fatalf("пустые поля не должны затирать данные: %+v", l)
	}
}

func TestDeleteDeviceSpecialChars(t *testing.T) {
	openDevicesDB(t)
	for _, h := range []string{"a/b", "../../etc/passwd", "q%2Fz", `x\y'");//`} {
		_, _ = TouchDevice(1, Device{HWID: h}, 0)
	}
	l, _ := ListDevices(1)
	if len(l) != 4 {
		t.Fatalf("ожидалось 4 устройства, есть %d", len(l))
	}
	for _, d := range l {
		_ = DeleteDevice(1, d.ID)
	}
	if l, _ := ListDevices(1); len(l) != 0 {
		t.Fatalf("устройства со спецсимволами должны удаляться, осталось %d", len(l))
	}
}
