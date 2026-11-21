package update

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckReleaseHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/VERSION" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("0.1-test.9\n"))
	}))
	defer srv.Close()
	i, err := CheckRelease(srv.URL, "0.1-test.8")
	if err != nil || !i.Available || i.Latest != "0.1-test.9" {
		t.Fatalf("%+v %v", i, err)
	}
	i, _ = CheckRelease(srv.URL, "0.1-test.9")
	if i.Available {
		t.Fatal("та же версия принята за обновление")
	}
}

func TestGitHubLatestRequiresCompleteStableRelease(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       string
	}{
		{"stable", `{"tag_name":"v1.2.3","assets":[{"name":"install.sh"},{"name":"SHA256SUMS"},{"name":"SHA256SUMS.sig"},{"name":"kitsune-linux-amd64"},{"name":"kitsune-linux-arm64"}]}`, "1.2.3"},
		{"no binaries", `{"tag_name":"v1.2.3","assets":[]}`, ""},
		{"prerelease", `{"tag_name":"v1.2.3","prerelease":true}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-token" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			got, err := versionViaGitHub(srv.URL, "test-token")
			if got != tc.want || (err != nil) != (tc.want == "") {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}
