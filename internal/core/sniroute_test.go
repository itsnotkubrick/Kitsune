package core

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// Настоящий ClientHello от crypto/tls: разбор SNI должен вернуть имя, а прочитанные байты – пересылаться целиком.
func TestPeekSNIFromRealClientHello(t *testing.T) {
	for _, name := range []string{"dl.google.com", "a.b.example.org", "x.io"} {
		srv, cli := net.Pipe()
		go func() {
			c := tls.Client(cli, &tls.Config{ServerName: name, InsecureSkipVerify: true, NextProtos: []string{"h2"}})
			_ = c.Handshake()
		}()
		got, buf, err := peekSNI(srv)
		srv.Close()
		cli.Close()
		if err != nil || got != name {
			t.Fatalf("peekSNI: %q, %v (ожидалось %q)", got, err, name)
		}
		if len(buf) < 5 || buf[0] != 0x16 {
			t.Fatalf("прочитанные байты потеряны: %v", buf[:min(5, len(buf))])
		}
	}
}

func TestPeekSNINotTLS(t *testing.T) {
	srv, cli := net.Pipe()
	go func() { _, _ = io.WriteString(cli, "GET / HTTP/1.1\r\n\r\n") }()
	sni, buf, err := peekSNI(srv)
	if err != nil || sni != "" || len(buf) != 5 {
		t.Fatalf("не-TLS: sni=%q len=%d err=%v", sni, len(buf), err)
	}
	srv.Close()
	cli.Close()
	_ = time.Now
}

func TestRouterLookup(t *testing.T) {
	r := &router{table: map[string]backend{"a.com": {addr: "127.0.0.1:1"}}, def: &backend{addr: "127.0.0.1:2"}}
	if b := r.lookup("A.com"); b == nil || b.addr != "127.0.0.1:1" {
		t.Fatal("имя ищется без учёта регистра")
	}
	if b := r.lookup("unknown.org"); b == nil || b.addr != "127.0.0.1:2" {
		t.Fatal("незнакомое имя уходит в подключение по умолчанию")
	}
	if b := r.lookup(""); b == nil || b.addr != "127.0.0.1:2" {
		t.Fatal("без SNI – по умолчанию")
	}
}

func TestRouterLookupFallsBackToDecoy(t *testing.T) {
	r := &router{table: map[string]backend{}, decoy: &backend{addr: "127.0.0.1:3"}}
	if b := r.lookup("x.org"); b == nil || b.addr != "127.0.0.1:3" {
		t.Fatal("без подключения по умолчанию соединение уходит на заглушку")
	}
	r.def = &backend{addr: "127.0.0.1:2"}
	if b := r.lookup("x.org"); b == nil || b.addr != "127.0.0.1:2" {
		t.Fatal("подключение по умолчанию важнее заглушки")
	}
	if (&router{}).lookup("x.org") != nil {
		t.Fatal("без бэкенда и без заглушки ответа нет")
	}
}

// Соединение без бэкенда по умолчанию доходит до заглушки с исходным ClientHello (а не обрывается молча).
func TestRouterForwardsToDecoy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("нет локального сокета")
	}
	defer ln.Close()
	got := make(chan byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 1)
		_, _ = io.ReadFull(c, b)
		got <- b[0]
	}()
	r := &router{table: map[string]backend{}, decoy: &backend{addr: ln.Addr().String()}}
	srv, cli := net.Pipe()
	go func() {
		c := tls.Client(cli, &tls.Config{ServerName: "unknown.example", InsecureSkipVerify: true})
		_ = c.Handshake()
	}()
	go r.handle(srv)
	select {
	case b := <-got:
		if b != 0x16 {
			t.Fatalf("на заглушку пришёл байт %#x, ожидался TLS handshake 0x16", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("соединение не дошло до заглушки")
	}
	srv.Close()
	cli.Close()
}
