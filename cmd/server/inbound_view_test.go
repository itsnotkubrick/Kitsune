package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
)

func TestViewInboundNeedsDomain(t *testing.T) {
	cases := []struct {
		kind, settings string
		want           bool
	}{
		{"naive", `{}`, true},
		{"naive", `{"sni":"vpn.example.com"}`, false},
		{"hysteria2", `{"cert_mode":"acme"}`, true},
		{"hysteria2", `{"cert_mode":"acme","sni":"vpn.example.com"}`, false},
		{"vless-reality", `{}`, false},
	}
	for _, c := range cases {
		v := viewInbound(db.Inbound{Kind: c.kind, Settings: c.settings}, 0)
		if v.NeedsDomain != c.want {
			t.Errorf("%s %s: needs_domain=%v, ждали %v", c.kind, c.settings, v.NeedsDomain, c.want)
		}
	}
}

func TestViewInboundHidesPrivateKeys(t *testing.T) {
	for _, kind := range []string{"vless-reality", "awg"} {
		v := viewInbound(db.Inbound{Kind: kind, PrivateKey: "PRIVSECRET", PublicKey: "PUBKEY",
			Settings: `{"private_key":"PRIVSECRET","public_key":"PUBKEY"}`}, 0)
		b, _ := json.Marshal(v)
		if bytes.Contains(b, []byte("PRIVSECRET")) || bytes.Contains(b, []byte(`"private_key"`)) {
			t.Errorf("%s: закрытый ключ в ответе: %s", kind, b)
		}
		if !bytes.Contains(b, []byte("PUBKEY")) || !v.HasPrivateKey || !bytes.Contains(b, []byte(`"has_private_key":true`)) {
			t.Errorf("%s: нет public_key/has_private_key: %s", kind, b)
		}
	}
	b, _ := json.Marshal(viewInbound(db.Inbound{Kind: "naive", Settings: `{}`}, 0))
	if !bytes.Contains(b, []byte(`"has_private_key":false`)) {
		t.Errorf("has_private_key должен быть false: %s", b)
	}
}

func TestMaskSecretKeys(t *testing.T) {
	cfg := map[string]any{"inbounds": []any{map[string]any{"streamSettings": map[string]any{
		"realitySettings": map[string]any{"privateKey": "PRIVSECRET", "shortIds": []any{"ab"}}}}},
		"outbounds": []any{map[string]any{"settings": map[string]any{"secretKey": "PRIVSECRET"}}}}
	b, _ := json.Marshal(maskSecretKeys(cfg))
	if bytes.Contains(b, []byte("PRIVSECRET")) || !bytes.Contains(b, []byte("shortIds")) {
		t.Errorf("маска не сработала: %s", b)
	}
}

func TestNoStoreHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/v1")
	g.Use(noStore())
	g.GET("/x", func(c *gin.Context) { c.String(200, "ok") })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/x", nil))
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
		t.Errorf("заголовки: %v", w.Header())
	}
}
