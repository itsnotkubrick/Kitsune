package core

import (
	"testing"
	"time"
)

func TestParseOnlineMatchesXrayOutput(t *testing.T) {
	raw := []byte(`{"users":[{"email":"dev@Shadowsocks","ips":[{"ip":"192.168.1.117","lastSeen":1791729006},{"ip":"10.0.0.5","lastSeen":1791729000}]}]}`)
	m, err := parseOnline(raw)
	if err != nil || len(m["dev@Shadowsocks"]) != 2 || m["dev@Shadowsocks"][0].IP != "192.168.1.117" {
		t.Fatalf("%v %v", m, err)
	}
	if m, err := parseOnline([]byte(`{}`)); err != nil || len(m) != 0 {
		t.Fatalf("пустой ответ: %v %v", m, err)
	}
}

func TestDecideDevicesKeepsOldestAddresses(t *testing.T) {
	base := time.Now()
	first := map[string]time.Time{"1.1.1.1": base, "2.2.2.2": base.Add(time.Minute), "3.3.3.3": base.Add(2 * time.Minute)}
	d := decideDevices(2, []string{"3.3.3.3", "1.1.1.1", "2.2.2.2"}, first)
	if len(d.Allowed) != 2 || d.Allowed[0] != "1.1.1.1" || d.Allowed[1] != "2.2.2.2" || len(d.Extra) != 1 || d.Extra[0] != "3.3.3.3" {
		t.Fatalf("%+v", d)
	}
	if d := decideDevices(3, []string{"1.1.1.1", "2.2.2.2"}, first); len(d.Extra) != 0 {
		t.Fatalf("в пределах лимита блокировать нечего: %+v", d)
	}
	if d := decideDevices(0, []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}, first); len(d.Extra) != 0 {
		t.Fatalf("лимит 0 – без ограничений: %+v", d)
	}
}
