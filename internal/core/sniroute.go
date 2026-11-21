package core

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"kitsune/internal/db"
	"kitsune/internal/proto"
)

// Режим «всё на 443»: панель сама слушает порт 443 и по имени сайта (SNI) из TLS ClientHello направляет
// соединение в нужное локальное подключение, не расшифровывая трафик. Незнакомое имя уходит в REALITY.

type backend struct {
	addr  string
	proxy bool // передавать заголовок PROXY protocol (настоящий адрес клиента)
}

type router struct {
	mu    sync.RWMutex
	ln    net.Listener
	table map[string]backend
	def   *backend
	// decoy – сайт-заглушка (self-steal): туда уходят соединения, для которых нет подключения по умолчанию. Живой веб-сервер
	// не обрывает соединение молча, поэтому зонд получает обычный TLS-ответ.
	decoy *backend
}

// DecoyAddr – адрес сайта-заглушки на своём домене (его слушает пакет selfsteal).
const DecoyAddr = "127.0.0.1:10399"

var decoyAddr = DecoyAddr // отдельная переменная ради тестов

func decoyBackend() *backend {
	if db.GetSetting("selfsteal_domain", "") == "" {
		return nil
	}
	return &backend{addr: decoyAddr}
}

var sniRouter = &router{}

func (r *router) lookup(sni string) *backend {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if b, ok := r.table[strings.ToLower(sni)]; ok {
		return &b
	}
	if r.def != nil {
		return r.def
	}
	return r.decoy
}

// peekSNI читает первую TLS-запись и достаёт из ClientHello имя сервера. buf – прочитанные байты для пересылки.
func peekSNI(c net.Conn) (sni string, buf []byte, err error) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	hdr := make([]byte, 5)
	if _, err = io.ReadFull(c, hdr); err != nil {
		return "", nil, err
	}
	buf = append(buf, hdr...)
	if hdr[0] != 0x16 { // не TLS handshake
		return "", buf, nil
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	if n < 4 || n > 16384 {
		return "", buf, nil
	}
	body := make([]byte, n)
	if _, err = io.ReadFull(c, body); err != nil {
		return "", buf, err
	}
	buf = append(buf, body...)
	return parseSNI(body), buf, nil
}

func parseSNI(b []byte) string {
	// handshake: type(1)=1, len(3), version(2), random(32), sid, ciphers, compression, extensions
	if len(b) < 42 || b[0] != 1 {
		return ""
	}
	p := 4 + 2 + 32
	skip := func(lenBytes int) bool {
		if p+lenBytes > len(b) {
			return false
		}
		n := 0
		for i := 0; i < lenBytes; i++ {
			n = n<<8 | int(b[p+i])
		}
		p += lenBytes + n
		return p <= len(b)
	}
	if !skip(1) || !skip(2) || !skip(1) { // session id, cipher suites, compression
		return ""
	}
	if p+2 > len(b) {
		return ""
	}
	extLen := int(b[p])<<8 | int(b[p+1])
	p += 2
	end := p + extLen
	if end > len(b) {
		end = len(b)
	}
	for p+4 <= end {
		typ := int(b[p])<<8 | int(b[p+1])
		l := int(b[p+2])<<8 | int(b[p+3])
		p += 4
		if p+l > end {
			return ""
		}
		if typ == 0 { // server_name
			e := b[p : p+l]
			if len(e) < 5 {
				return ""
			}
			// список: len(2), тип(1)=0, длина имени(2), имя
			if e[2] != 0 {
				return ""
			}
			nl := int(e[3])<<8 | int(e[4])
			if 5+nl > len(e) {
				return ""
			}
			return string(e[5 : 5+nl])
		}
		p += l
	}
	return ""
}

func proxyHeader(c net.Conn) string {
	src, ok1 := c.RemoteAddr().(*net.TCPAddr)
	dst, ok2 := c.LocalAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return "PROXY UNKNOWN\r\n"
	}
	fam := "TCP4"
	if src.IP.To4() == nil {
		fam = "TCP6"
	}
	return fmt.Sprintf("PROXY %s %s %s %d %d\r\n", fam, src.IP, dst.IP, src.Port, dst.Port)
}

func (r *router) handle(c net.Conn) {
	defer c.Close()
	sni, buf, err := peekSNI(c)
	if err != nil {
		return
	}
	b := r.lookup(sni)
	if b == nil {
		return
	}
	up, err := net.DialTimeout("tcp", b.addr, 5*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	if b.proxy {
		if _, err := io.WriteString(up, proxyHeader(c)); err != nil {
			return
		}
	}
	if _, err := up.Write(buf); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(up, c)
	go pipe(c, up)
	<-done
	<-done
}

func (r *router) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(30 * time.Second)
		}
		go r.handle(c)
	}
}

// ApplyRouter включает или выключает маршрутизатор на 443 и обновляет таблицу имён.
func ApplyRouter() error {
	env := PublicEnv()
	if !env.Single {
		sniRouter.stop()
		return nil
	}
	inbounds, err := db.GetInbounds()
	if err != nil {
		return err
	}
	table := map[string]backend{}
	var def *backend
	for _, ib := range inbounds {
		if !ib.Enable || !proto.Routed(ib, env) {
			continue
		}
		b := backend{addr: fmt.Sprintf("127.0.0.1:%d", proto.InnerPort(ib.ID)), proxy: ib.Kind != string(proto.MTProto)}
		for _, name := range proto.RoutableNames(ib) {
			name = strings.ToLower(name)
			if _, dup := table[name]; dup {
				return fmt.Errorf("имя %s используется двумя подключениями – в режиме «всё на 443» имена должны различаться", name)
			}
			table[name] = b
		}
		if def == nil && ib.Kind == string(proto.VlessReality) {
			bb := b
			def = &bb
		}
	}
	if len(table) == 0 {
		sniRouter.stop()
		return errors.New("в режиме «всё на 443» нет подключений, которые можно вынести на 443 (нужен REALITY или TLS-подключение с доменом)")
	}
	sniRouter.mu.Lock()
	sniRouter.table, sniRouter.def, sniRouter.decoy = table, def, decoyBackend()
	needListen := sniRouter.ln == nil
	sniRouter.mu.Unlock()
	if needListen {
		ln, err := net.Listen("tcp", ":443")
		if err != nil {
			return fmt.Errorf("не удалось занять порт 443 (он занят или нужны права root): %w", err)
		}
		sniRouter.mu.Lock()
		sniRouter.ln = ln
		sniRouter.mu.Unlock()
		go sniRouter.serve(ln)
	}
	return nil
}

func (r *router) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ln != nil {
		_ = r.ln.Close()
		r.ln = nil
	}
	r.table, r.def = nil, nil
}

// RouterRunning – слушает ли маршрутизатор порт 443.
func RouterRunning() bool {
	sniRouter.mu.RLock()
	defer sniRouter.mu.RUnlock()
	return sniRouter.ln != nil
}
