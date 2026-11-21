package main

import (
	"errors"
	"github.com/gin-gonic/gin"
	"kitsune/internal/bridge"
	"kitsune/internal/db"
	"kitsune/internal/proto"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBridgeScriptRejectsMalformedAndNone(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/script", handleBridgeScript)
	for _, body := range []string{`{`, `{"selection_mode":"invalid"}`, `{"selection_mode":"selected","only":[]}`, `{"selection_mode":"none"}`} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/script", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Fatalf("%s: %d", body, w.Code)
		}
	}
}
func TestBridgeBindingsRespectSelection(t *testing.T) {
	in := []db.Inbound{{Tag: "A", Kind: string(proto.VlessReality), Enable: true}, {Tag: "B", Kind: string(proto.VlessReality), Enable: true}}
	nodes := []bridge.Node{{Enabled: true, SNI: "www.example.com", Only: []string{"A"}}}
	if got := bridgeBindings(nodes, in); len(got) != 1 || got[0] != "A/www.example.com" {
		t.Fatalf("%v", got)
	}
	nodes[0].SelectionMode = "none"
	if got := bridgeBindings(nodes, in); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

func TestBridgeCoreFailureRestoresNodes(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	if _, err := db.DB.Exec(`INSERT INTO inbounds(tag,protocol,port,enable,kind,settings) VALUES('A','vless',443,1,'vless-reality','{}')`); err != nil {
		t.Fatal(err)
	}
	previous, err := bridge.Save([]bridge.Node{{Name: "old", Host: "203.0.113.7", Enabled: true, SNI: "old.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	original := bridgeApplyCores
	defer func() { bridgeApplyCores = original }()
	calls := 0
	bridgeApplyCores = func() error {
		calls++
		if calls == 1 {
			p := &proto.Profile{Kind: proto.VlessReality, Name: "A", Host: "vpn.example.net", Port: 443}
			if got := bridge.Expand([]*proto.Profile{p}); len(got) != 2 || got[1].Host != previous[0].Host {
				t.Error("staged nodes published")
			}
			return errors.New("test core validation failure")
		}
		return nil
	}
	r := gin.New()
	r.PUT("/bridges", handleBridgesSet)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/bridges", strings.NewReader(`{"nodes":[]}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != 500 || calls != 2 {
		t.Fatalf("status=%d apply calls=%d", w.Code, calls)
	}
	if got := bridge.List(); len(got) != 1 || got[0].ID != previous[0].ID {
		t.Fatalf("nodes not restored: %+v", got)
	}
}
func TestBridgeRoutesRequireSessionAndSameOrigin(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	r := idleRouter()
	r.Use(csrfGuard())
	registerBridgeRoutes(r.Group("/api/v1", AuthRequired()))
	for _, route := range []struct{ method, path string }{{"GET", "/bridges"}, {"PUT", "/bridges"}, {"POST", "/bridges/script"}, {"POST", "/bridges/check"}} {
		req := httptest.NewRequest(route.method, "http://panel.test/api/v1"+route.path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 401 {
			t.Fatalf("%s %s: %d", route.method, route.path, w.Code)
		}
	}
	jar := login(t, r)
	req := httptest.NewRequest("PUT", "http://panel.test/api/v1/bridges", strings.NewReader(`{"nodes":[]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	for _, c := range jar {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("cross-origin accepted: %d", w.Code)
	}
}
