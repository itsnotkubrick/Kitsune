package awg_test

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"

	"kitsune/internal/awg"
	"kitsune/internal/proto"
)

func hexKey(b64 string) string {
	raw, _ := base64.StdEncoding.DecodeString(b64)
	return hex.EncodeToString(raw)
}

func run(t *testing.T, kind proto.Kind, port int) {
	var s proto.Settings
	if err := s.Fill(kind); err != nil {
		t.Fatal(err)
	}
	peer, err := proto.NewAWGPeer(s.Subnet, nil)
	if err != nil {
		t.Fatal(err)
	}
	srvAddr, _ := proto.ServerAddr(s.Subnet)
	srvIP := netip.MustParsePrefix(srvAddr).Addr()
	cfg := awg.Config{Name: "t", Port: port, MTU: 1280, PrivateKey: s.PrivateKey, Address: srvAddr,
		Params: awg.Params{Jc: s.Jc, Jmin: s.Jmin, Jmax: s.Jmax, S1: s.S1, S2: s.S2, S3: s.S3, S4: s.S4, H1: s.H1, H2: s.H2, H3: s.H3, H4: s.H4,
			I1: s.I1, HeaderProtectionKey: s.HeaderKey},
		Peers: []awg.Peer{{PublicKey: peer.PublicKey, PSK: peer.PSK, AllowedIP: peer.IP + "/32"}}}

	// сервер в netstack
	stun, snet, err := netstack.CreateNetTUN([]netip.Addr{srvIP}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := awg.Start(cfg, stun)
	if err != nil {
		t.Fatalf("сервер: %v", err)
	}
	defer srv.Close()
	ln, err := snet.ListenTCP(&net.TCPAddr{Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "hello-through-awg") }))

	// клиент в netstack, настройки – ровно как в выданном клиенту конфиге
	ctun, cnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(peer.IP)}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	cdev := device.NewDevice(ctun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "client: "))
	defer cdev.Close()
	// ключ защиты заголовков клиент берёт из выданного конфига (base64), сервер хранит его в hex
	clientKey := ""
	for _, ln := range strings.Split((&proto.Profile{AWG: &peer, S: s, Host: "203.0.113.5", Port: port}).AWGConfig(), "\n") {
		if v, ok := strings.CutPrefix(ln, "HeaderProtectionKey = "); ok {
			raw, err := base64.StdEncoding.DecodeString(v)
			if err != nil || len(raw) != 32 {
				t.Fatalf("ключ в клиентском конфиге не base64 на 32 байта: %q", v)
			}
			clientKey = hex.EncodeToString(raw)
		}
	}
	if clientKey != s.HeaderKey {
		t.Fatalf("ключ клиента %q не совпадает с серверным %q", clientKey, s.HeaderKey)
	}
	uapi := fmt.Sprintf("private_key=%s\n", hexKey(peer.PrivateKey))
	for _, kv := range [][2]string{{"jc", s.Jc}, {"jmin", s.Jmin}, {"jmax", s.Jmax}, {"s1", s.S1}, {"s2", s.S2}, {"s3", s.S3}, {"s4", s.S4},
		{"h1", s.H1}, {"h2", s.H2}, {"h3", s.H3}, {"h4", s.H4}, {"i1", s.I1}, {"header_protection_key", clientKey}} {
		if kv[1] != "" {
			uapi += fmt.Sprintf("%s=%s\n", kv[0], kv[1])
		}
	}
	uapi += fmt.Sprintf("public_key=%s\npreshared_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=%s/32\npersistent_keepalive_interval=1\n",
		hexKey(s.PublicKey), hexKey(peer.PSK), port, srvIP)
	if err := cdev.IpcSet(uapi); err != nil {
		t.Fatalf("клиент IpcSet: %v", err)
	}
	if err := cdev.Up(); err != nil {
		t.Fatal(err)
	}

	hc := &http.Client{Transport: &http.Transport{DialContext: cnet.DialContext}, Timeout: 8 * time.Second}
	var body []byte
	for i := 0; i < 5; i++ {
		resp, err := hc.Get("http://" + srvIP.String() + ":8080/")
		if err == nil {
			body, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			break
		}
		time.Sleep(time.Second)
	}
	if string(body) != "hello-through-awg" {
		t.Fatalf("%s: ответ через туннель не получен (%q)", kind, body)
	}
	t.Logf("%s: туннель работает, клиентский конфиг:\n%s", kind, (&proto.Profile{AWG: &peer, S: s, Host: "203.0.113.5", Port: port}).AWGConfig())
}

func TestAWGClassic(t *testing.T) { run(t, proto.AWG, 51831) }
func TestAWG31(t *testing.T)      { run(t, proto.AWG3, 51832) }
