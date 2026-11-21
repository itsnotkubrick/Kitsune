// Package acct – локальный SOCKS5-прокси со счётчиками трафика по пользователям.
//
// У sing-box (TUIC, NaiveProxy) в готовых сборках нет счётчиков по пользователям. Поэтому трафик каждого
// пользователя sing-box пускает через этот прокси: он точно считает байты (TCP и UDP) и уходит в интернет сам.
// Прокси слушает только 127.0.0.1 и требует одноразовый токен; по желанию не пускает в локальные сети сервера.
package acct

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type Proxy struct {
	ln    net.Listener
	token string

	mu      sync.Mutex
	counts  map[string]int64
	private atomic.Bool // запрещать адреса локальных сетей
}

func New() (*Proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	p := &Proxy{ln: ln, token: hex.EncodeToString(b), counts: map[string]int64{}}
	p.private.Store(true)
	go p.serve()
	return p, nil
}

func (p *Proxy) Port() int           { return p.ln.Addr().(*net.TCPAddr).Port }
func (p *Proxy) Token() string       { return p.token }
func (p *Proxy) Close()              { _ = p.ln.Close() }
func (p *Proxy) BlockPrivate(v bool) { p.private.Store(v) }

// Drain возвращает накопленные байты по пользователям и обнуляет счётчики.
func (p *Proxy) Drain() map[string]int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.counts
	p.counts = map[string]int64{}
	return out
}

func (p *Proxy) add(user string, n int64) {
	if n <= 0 {
		return
	}
	p.mu.Lock()
	p.counts[user] += n
	p.mu.Unlock()
}

func (p *Proxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

const (
	cmdConnect = 1
	cmdUDP     = 3
)

func (p *Proxy) handshake(c net.Conn) (user string, err error) {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	hdr := make([]byte, 2)
	if _, err = io.ReadFull(c, hdr); err != nil || hdr[0] != 5 {
		return "", errors.New("не SOCKS5")
	}
	methods := make([]byte, hdr[1])
	if _, err = io.ReadFull(c, methods); err != nil {
		return "", err
	}
	ok := false
	for _, m := range methods {
		if m == 2 {
			ok = true
		}
	}
	if !ok {
		_, _ = c.Write([]byte{5, 0xff})
		return "", errors.New("нужна авторизация по паролю")
	}
	_, _ = c.Write([]byte{5, 2})
	ver := make([]byte, 2)
	if _, err = io.ReadFull(c, ver); err != nil || ver[0] != 1 {
		return "", errors.New("неверная авторизация")
	}
	u := make([]byte, ver[1])
	if _, err = io.ReadFull(c, u); err != nil {
		return "", err
	}
	pl := make([]byte, 1)
	if _, err = io.ReadFull(c, pl); err != nil {
		return "", err
	}
	pw := make([]byte, pl[0])
	if _, err = io.ReadFull(c, pw); err != nil {
		return "", err
	}
	if subtle.ConstantTimeCompare(pw, []byte(p.token)) != 1 {
		_, _ = c.Write([]byte{1, 1})
		return "", errors.New("неверный токен")
	}
	_, _ = c.Write([]byte{1, 0})
	return string(u), nil
}

func readAddr(r io.Reader, atyp byte) (host string, err error) {
	switch atyp {
	case 1:
		b := make([]byte, 4)
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		return net.IP(b).String(), nil
	case 4:
		b := make([]byte, 16)
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		return net.IP(b).String(), nil
	case 3:
		l := make([]byte, 1)
		if _, err = io.ReadFull(r, l); err != nil {
			return
		}
		b := make([]byte, l[0])
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		return string(b), nil
	}
	return "", errors.New("неизвестный тип адреса")
}

func reply(c net.Conn, code byte, addr net.Addr) {
	ip, port := net.IPv4zero, 0
	if a, ok := addr.(*net.TCPAddr); ok {
		ip, port = a.IP, a.Port
	} else if a, ok := addr.(*net.UDPAddr); ok {
		ip, port = a.IP, a.Port
	}
	out := []byte{5, code, 0}
	if v4 := ip.To4(); v4 != nil {
		out = append(out, 1)
		out = append(out, v4...)
	} else {
		out = append(out, 4)
		out = append(out, ip.To16()...)
	}
	out = binary.BigEndian.AppendUint16(out, uint16(port))
	_, _ = c.Write(out)
}

func isPrivate(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// 100.64.0.0/10 (общие адреса операторов, у части хостеров там служебные сервисы) и 198.18.0.0/15 (стенды)
		return (v4[0] == 100 && v4[1]&0xc0 == 64) || (v4[0] == 198 && v4[1]&0xfe == 18)
	}
	return false
}

// resolve находит адрес и применяет запрет локальных сетей.
func (p *Proxy) resolve(host string) (net.IP, error) {
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		var err error
		ips, err = net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("имя не найдено")
		}
	}
	for _, ip := range ips {
		if p.private.Load() && isPrivate(ip) {
			continue
		}
		return ip, nil
	}
	return nil, errors.New("адрес в локальной сети запрещён")
}

func (p *Proxy) handle(c net.Conn) {
	defer c.Close()
	user, err := p.handshake(c)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[0] != 5 {
		return
	}
	host, err := readAddr(c, req[3])
	if err != nil {
		reply(c, 8, nil)
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	port := int(binary.BigEndian.Uint16(pb))

	switch req[1] {
	case cmdConnect:
		ip, err := p.resolve(host)
		if err != nil {
			reply(c, 2, nil) // соединение запрещено правилами
			return
		}
		up, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)), 10*time.Second)
		if err != nil {
			reply(c, 5, nil)
			return
		}
		defer up.Close()
		reply(c, 0, up.LocalAddr())
		p.relay(c, up, user)
	case cmdUDP:
		p.udp(c, user)
	default:
		reply(c, 7, nil)
	}
}

// relay гоняет байты в обе стороны и считает их.
func (p *Proxy) relay(a, b net.Conn, user string) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		n, _ := io.Copy(dst, src)
		p.add(user, n)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(b, a)
	go cp(a, b)
	<-done
	<-done
}

// udp: UDP ASSOCIATE. Датаграммы клиента (обёрнутые заголовком SOCKS5) пересылаются адресату, ответы – обратно.
func (p *Proxy) udp(ctrl net.Conn, user string) {
	cl, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		reply(ctrl, 1, nil)
		return
	}
	defer cl.Close()
	out, err := net.ListenUDP("udp", nil)
	if err != nil {
		reply(ctrl, 1, nil)
		return
	}
	defer out.Close()
	reply(ctrl, 0, cl.LocalAddr())

	var clientAddr atomic.Pointer[net.UDPAddr]
	var sentTo sync.Map // адресаты, которым клиент уже слал: от остальных пакеты не принимаем и в трафик не считаем
	go func() {         // ответы от адресатов -> клиенту
		buf := make([]byte, 65535)
		for {
			n, from, err := out.ReadFromUDP(buf)
			if err != nil {
				return
			}
			ca := clientAddr.Load()
			if ca == nil {
				continue
			}
			if _, ok := sentTo.Load(from.String()); !ok {
				continue
			}
			p.add(user, int64(n))
			pkt := []byte{0, 0, 0}
			if v4 := from.IP.To4(); v4 != nil {
				pkt = append(pkt, 1)
				pkt = append(pkt, v4...)
			} else {
				pkt = append(pkt, 4)
				pkt = append(pkt, from.IP.To16()...)
			}
			pkt = binary.BigEndian.AppendUint16(pkt, uint16(from.Port))
			pkt = append(pkt, buf[:n]...)
			_, _ = cl.WriteToUDP(pkt, ca)
		}
	}()
	go func() { // датаграммы клиента -> адресатам
		buf := make([]byte, 65535)
		for {
			n, from, err := cl.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !from.IP.IsLoopback() { // слушаем только локальный клиент
				continue
			}
			if n < 10 || buf[2] != 0 { // фрагментацию не поддерживаем
				continue
			}
			clientAddr.Store(from)
			r := &sliceReader{b: buf[4:n]}
			host, err := readAddr(r, buf[3])
			if err != nil || len(r.b) < 2 {
				continue
			}
			port := int(binary.BigEndian.Uint16(r.b[:2]))
			data := r.b[2:]
			ip, err := p.resolve(host)
			if err != nil {
				continue
			}
			p.add(user, int64(len(data)))
			dst := &net.UDPAddr{IP: ip, Port: port}
			sentTo.Store(dst.String(), struct{}{})
			_, _ = out.WriteToUDP(data, dst)
		}
	}()
	// ассоциация живёт, пока открыто управляющее TCP-соединение
	_, _ = io.Copy(io.Discard, ctrl)
}

type sliceReader struct{ b []byte }

func (s *sliceReader) Read(p []byte) (int, error) {
	if len(s.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.b)
	s.b = s.b[n:]
	return n, nil
}

var _ = fmt.Sprintf
