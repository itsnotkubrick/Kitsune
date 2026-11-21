package bridge

import (
	"context"
	"kitsune/internal/db"
	"kitsune/internal/proto"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestInstallerLifecycle(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 required for isolated installer execution")
	}
	dir := t.TempDir()
	for _, spec := range []struct {
		name, ip string
		port     int
	}{{"first", "198.51.100.20", 443}, {"second", "198.51.100.21", 8443}} {
		s, err := Script(spec.ip, []Forward{{"tcp", spec.port}, {"udp", spec.port}})
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, spec.name)
		if err := os.WriteFile(p, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("bash", "-n", p).CombinedOutput(); err != nil {
			t.Fatalf("syntax: %v %s", err, out)
		}
	}
	cmd := exec.Command(python, "testdata/lifecycle.py", filepath.Join(dir, "first"), filepath.Join(dir, "second"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("lifecycle: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}
func TestBothAndPortValidation(t *testing.T) {
	ib := db.Inbound{Enable: true, Tag: "SS", Kind: string(proto.SS2022), Port: 8388}
	fw := Forwards([]db.Inbound{ib}, proto.Env{})
	if len(fw) != 2 || fw[0].Proto != "tcp" || fw[1].Proto != "udp" {
		t.Fatalf("%+v", fw)
	}
	if _, err := Script("198.51.100.20", fw); err != nil {
		t.Fatal(err)
	}
	ib.Settings = `{"external_port":"9999"}`
	if ValidatePorts([]db.Inbound{ib}, proto.Env{}) == nil {
		t.Fatal("mismatched external port accepted")
	}
	for _, host := range []string{"100.64.0.1", "240.0.0.1", "255.255.255.255", "0.1.2.3", "198.18.0.1", "192.0.0.1"} {
		if CheckHost(host) == nil {
			t.Errorf("accepted %s", host)
		}
	}
}
func TestSelectionAndUDPAvailability(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	for _, mode := range []string{"", "all", "none", "selected"} {
		n := Node{Name: "test", Host: "203.0.113.7", Only: []string{"tcp"}, SelectionMode: mode}
		v, err := Validate([]Node{n})
		if err != nil {
			t.Fatal(err)
		}
		if got := v[0].Takes("tcp"); got != (mode != "none") {
			t.Errorf("%s: %v", mode, got)
		}
	}
	nodes, err := Save([]Node{{Name: "test", Host: "203.0.113.7", Enabled: true, AutoHide: true}})
	if err != nil {
		t.Fatal(err)
	}
	n := nodes[0]
	for i := 0; i < 3; i++ {
		ObserveNode(n, true, false, 0, time.Now(), []PortStatus{{Proto: "tcp", Port: 443}})
	}
	profiles := []*proto.Profile{prof(proto.VlessReality, "vpn.example.net", "www.example.com"), prof(proto.Hysteria2, "vpn.example.net", "www.example.com")}
	if out := Expand(profiles); len(out) != 3 || out[2].Kind != proto.Hysteria2 {
		t.Fatalf("UDP hidden: %+v", out)
	}
	changed := n
	changed.Host = "198.51.100.9"
	if DownNode(changed) {
		t.Fatal("stale failure inherited by changed node")
	}
	ObserveNode(n, true, false, 0, time.Now().Add(-10*time.Minute))
	if DownNode(n) {
		t.Fatal("expired observation hides a node")
	}
}
func TestProbePortsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results := ProbePorts(ctx, "203.0.113.7", []Forward{{"tcp", 443}, {"udp", 443}})
	if len(results) != 2 || results[0].OK || results[1].OK || results[1].Note == "" {
		t.Fatalf("%+v", results)
	}
}
func TestProbePortsTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	results := ProbePorts(context.Background(), "127.0.0.1", []Forward{{"tcp", port}})
	if len(results) != 1 || !results[0].OK {
		t.Fatalf("%+v", results)
	}
}

func TestFreezeSubscriptionsAndScopedNames(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	old, err := Save([]Node{{Name: "old", Host: "203.0.113.7", Enabled: true, SNI: "old.example.com", Only: []string{"A"}}})
	if err != nil {
		t.Fatal(err)
	}
	release := FreezeSubscriptions(old)
	defer release()
	_, err = Save([]Node{{Name: "new", Host: "198.51.100.9", Enabled: true, SNI: "new.example.com", Only: []string{"B"}}})
	if err != nil {
		t.Fatal(err)
	}
	a := prof(proto.VlessReality, "vpn.example.net", "www.example.com")
	a.Name = "A"
	b := prof(proto.VlessReality, "vpn.example.net", "www.example.com")
	b.Name = "B"
	if got := Expand([]*proto.Profile{a, b}); len(got) != 3 || got[2].Host != "203.0.113.7" {
		t.Fatalf("staged subscription leaked: %+v", got)
	}
	if names := proto.InboundRealitySNIs("A"); len(names) != 0 {
		t.Fatalf("unselected names: %v", names)
	}
	if names := proto.InboundRealitySNIs("B"); len(names) != 1 || names[0] != "new.example.com" {
		t.Fatalf("missing staged names: %v", names)
	}
	release()
	if got := Expand([]*proto.Profile{a, b}); len(got) != 3 || got[2].Host != "198.51.100.9" {
		t.Fatalf("commit not published: %+v", got)
	}
}

func TestPerPortHealthAndRecovery(t *testing.T) {
	n := Node{ID: "portchecks", Host: "203.0.113.7"}
	now := time.Now()
	for i := 0; i < 3; i++ {
		ObserveNode(n, true, true, 1, now, []PortStatus{{Proto: "tcp", Port: 443, OK: true}, {Proto: "tcp", Port: 8443, OK: false}, {Proto: "udp", Port: 443}})
	}
	if ProfileDown(n, 443) || !ProfileDown(n, 8443) || ProfileDown(n, 9443) {
		t.Fatal("port failures must be independent")
	}
	for i := 0; i < 2; i++ {
		ObserveNode(n, true, true, 1, now, []PortStatus{{Proto: "tcp", Port: 443, OK: true}, {Proto: "tcp", Port: 8443, OK: true}})
		if ProfileDown(n, 8443) != (i == 0) {
			t.Fatal("recovery must require two successes")
		}
	}
}

// Run explicitly on a Linux host that permits user/network namespaces and has nft.
// All forwarding is confined to temporary namespaces; systemd is a command double.
func TestInstallerNetworkNamespaces(t *testing.T) {
	if os.Getenv("KITSUNE_BRIDGE_NETNS") != "1" {
		t.Skip("set KITSUNE_BRIDGE_NETNS=1 to run real nftables integration")
	}
	dir := t.TempDir()
	for i, port := range []int{18443, 18444} {
		s, err := Script("198.51.100.20", []Forward{{"tcp", port}, {"udp", port}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, []string{"first", "second"}[i]), []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "unshare", "-Urn", "bash", "testdata/netns.sh", filepath.Join(dir, "first"), filepath.Join(dir, "second"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("network integration: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}
