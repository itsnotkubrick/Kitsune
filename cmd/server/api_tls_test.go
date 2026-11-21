package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"kitsune/internal/core"
)

func TestPlainHandlerRequiresHTTPSForSubscriptions(t *testing.T) {
	old := panelCfg.Swap(&core.PanelTLS{Mode: "self", Port: 8443, Redirect: true})
	t.Cleanup(func() { panelCfg.Store(old) })
	t.Setenv("KITSUNE_TRUSTED_PROXIES", "10.0.0.1")
	handler := plainHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct {
		path      string
		peer      string
		forwarded string
		want      int
	}{
		{"/sub/test", "10.0.0.2:1234", "", http.StatusForbidden},
		{"/sub/test", "10.0.0.2:1234", "https", http.StatusForbidden},
		{"/sub/test", "10.0.0.1:1234", "https", http.StatusNoContent},
		{"/api/health", "10.0.0.2:1234", "", http.StatusNoContent},
		{"/", "10.0.0.2:1234", "", http.StatusTemporaryRedirect},
	} {
		req := httptest.NewRequest(http.MethodGet, "http://panel.test"+tc.path, nil)
		req.RemoteAddr = tc.peer
		req.Header.Set("X-Forwarded-Proto", tc.forwarded)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Errorf("%s from %s (%q): got %d, want %d", tc.path, tc.peer, tc.forwarded, w.Code, tc.want)
		}
	}
}
