package acct

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func dial(t *testing.T, p *Proxy, user, token string) net.Conn {
	c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(p.Port()))
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte{5, 1, 2})
	r := make([]byte, 2)
	io.ReadFull(c, r)
	auth := append([]byte{1, byte(len(user))}, user...)
	auth = append(auth, byte(len(token)))
	auth = append(auth, token...)
	c.Write(auth)
	io.ReadFull(c, r)
	if r[1] != 0 {
		c.Close()
		return nil
	}
	return c
}

func request(c net.Conn, cmd byte, ip net.IP, port int) byte {
	req := append([]byte{5, cmd, 0, 1}, ip.To4()...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	c.Write(req)
	rep := make([]byte, 10)
	io.ReadFull(c, rep)
	return rep[1]
}

func TestConnectCountsBothDirections(t *testing.T) {
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err == nil {
			io.Copy(c, c)
			c.Close()
		}
	}()
	p, _ := New()
	defer p.Close()
	p.BlockPrivate(false)
	c := dial(t, p, "alice@TUIC", p.Token())
	if c == nil {
		t.Fatal("авторизация не прошла")
	}
	if code := request(c, cmdConnect, net.IPv4(127, 0, 0, 1), echo.Addr().(*net.TCPAddr).Port); code != 0 {
		t.Fatalf("код ответа %d", code)
	}
	msg := bytes.Repeat([]byte("x"), 1000)
	c.Write(msg)
	got := make([]byte, 1000)
	io.ReadFull(c, got)
	c.Close()
	time.Sleep(300 * time.Millisecond)
	if n := p.Drain()["alice@TUIC"]; n != 2000 {
		t.Fatalf("учтено %d байт, ожидалось 2000 (1000 туда и 1000 обратно)", n)
	}
	if len(p.Drain()) != 0 {
		t.Fatal("после Drain счётчики должны быть пустыми")
	}
}

func TestRejectsWrongTokenAndPrivateTargets(t *testing.T) {
	p, _ := New()
	defer p.Close()
	if dial(t, p, "x", "wrong") != nil {
		t.Fatal("с неверным токеном пускать нельзя")
	}
	c := dial(t, p, "bob@Naive", p.Token())
	if code := request(c, cmdConnect, net.IPv4(127, 0, 0, 1), 8080); code == 0 {
		t.Fatal("доступ к 127.0.0.1 должен быть запрещён (локальный интерфейс панели)")
	}
	c.Close()
	c = dial(t, p, "bob@Naive", p.Token())
	if code := request(c, cmdConnect, net.IPv4(192, 168, 1, 1), 80); code == 0 {
		t.Fatal("доступ к локальной сети должен быть запрещён")
	}
	c.Close()
}

func TestUDPAssociateRelaysAndCounts(t *testing.T) {
	srv, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer srv.Close()
	go func() {
		buf := make([]byte, 100)
		for {
			n, a, err := srv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			srv.WriteToUDP(buf[:n], a)
		}
	}()
	p, _ := New()
	defer p.Close()
	p.BlockPrivate(false)
	c := dial(t, p, "carol@TUIC", p.Token())
	req := []byte{5, cmdUDP, 0, 1, 0, 0, 0, 0, 0, 0}
	c.Write(req)
	rep := make([]byte, 10)
	io.ReadFull(c, rep)
	if rep[1] != 0 {
		t.Fatalf("UDP ASSOCIATE: %d", rep[1])
	}
	relay := &net.UDPAddr{IP: net.IP(rep[4:8]), Port: int(binary.BigEndian.Uint16(rep[8:10]))}
	u, _ := net.DialUDP("udp", nil, relay)
	defer u.Close()
	pkt := []byte{0, 0, 0, 1, 127, 0, 0, 1}
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(srv.LocalAddr().(*net.UDPAddr).Port))
	pkt = append(pkt, []byte("ping-12345")...)
	u.Write(pkt)
	u.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 200)
	n, err := u.Read(buf)
	if err != nil || !bytes.HasSuffix(buf[:n], []byte("ping-12345")) {
		t.Fatalf("ответ через UDP-прокси не получен: %v %q", err, buf[:n])
	}
	time.Sleep(200 * time.Millisecond)
	if got := p.Drain()["carol@TUIC"]; got != 20 {
		t.Fatalf("учтено %d байт, ожидалось 20", got)
	}
}

func TestIsPrivateCoversCGNATAndBenchmark(t *testing.T) {
	for ip, want := range map[string]bool{
		"100.64.0.1": true, "100.127.255.254": true, "100.128.0.1": false, "100.63.255.255": false,
		"198.18.0.1": true, "198.19.255.255": true, "198.20.0.1": false, "198.17.255.255": false,
		"10.1.2.3": true, "127.0.0.1": true, "8.8.8.8": false,
	} {
		if got := isPrivate(net.ParseIP(ip)); got != want {
			t.Errorf("%s: %v, ждали %v", ip, got, want)
		}
	}
}
