package site

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func probe(method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, req)
	return w
}

func setup() {
	SetPage("<html>страница</html>\n")
	SetSalt("salt-a")
}

// Профиль «статический сайт на nginx»: страница на «/», HTML-страница ошибки на остальных путях, 405 на не-GET/HEAD.
func TestProbes(t *testing.T) {
	setup()
	for _, tc := range []struct {
		method, target string
		code           int
		body           string // "page" – страница, "404"/"405" – страница ошибки, "" – без тела
	}{
		{"GET", "/", 200, "page"}, {"GET", "/index.html", 200, "page"}, {"GET", "//", 200, "page"}, {"GET", "/?x=1", 200, "page"},
		{"HEAD", "/", 200, ""},
		{"GET", "/favicon.ico", 404, "404"}, {"GET", "/robots.txt", 404, "404"}, {"GET", "/что-угодно", 404, "404"}, {"HEAD", "/x", 404, ""},
		{"POST", "/", 405, "405"}, {"PUT", "/", 405, "405"}, {"DELETE", "/", 405, "405"}, {"OPTIONS", "/", 405, "405"}, {"POST", "/favicon.ico", 405, "405"},
	} {
		w := probe(tc.method, tc.target, nil)
		h := w.Header()
		if w.Code != tc.code {
			t.Errorf("%s %s: код %d, ожидался %d", tc.method, tc.target, w.Code, tc.code)
		}
		if h.Get("Server") != "nginx" || h.Get("Content-Type") != "text/html" {
			t.Errorf("%s %s: заголовки %v", tc.method, tc.target, h)
		}
		switch tc.body {
		case "page":
			if w.Body.String() != current() || h.Get("ETag") == "" || h.Get("Last-Modified") == "" || h.Get("Accept-Ranges") != "bytes" {
				t.Errorf("%s %s: страница или валидаторы: %v", tc.method, tc.target, h)
			}
		case "404":
			if w.Body.String() != NotFoundBody || h.Get("ETag") != "" || h.Get("Last-Modified") != "" {
				t.Errorf("%s %s: страница 404 или лишние валидаторы: %v", tc.method, tc.target, h)
			}
		case "405":
			if w.Body.String() != notAllowedBody {
				t.Errorf("%s %s: страница 405 %q", tc.method, tc.target, w.Body.String())
			}
		case "":
			if w.Body.Len() != 0 {
				t.Errorf("%s %s: у HEAD есть тело", tc.method, tc.target)
			}
		}
		if strings.Contains(w.Body.String(), "404 page not found") {
			t.Errorf("%s %s: текст Go вместо страницы nginx", tc.method, tc.target)
		}
	}
}

func TestConditionalAndRange(t *testing.T) {
	setup()
	first := probe("GET", "/", nil)
	etag, lm := first.Header().Get("ETag"), first.Header().Get("Last-Modified")
	if w := probe("GET", "/", map[string]string{"If-None-Match": etag}); w.Code != 304 || w.Body.Len() != 0 || w.Header().Get("ETag") != etag {
		t.Errorf("If-None-Match: %d %v", w.Code, w.Header())
	}
	if w := probe("GET", "/", map[string]string{"If-Modified-Since": lm}); w.Code != 304 {
		t.Errorf("If-Modified-Since: %d", w.Code)
	}
	if w := probe("GET", "/", map[string]string{"If-None-Match": `"другой"`}); w.Code != 200 {
		t.Errorf("чужой ETag должен давать 200, а не %d", w.Code)
	}
	w := probe("GET", "/", map[string]string{"Range": "bytes=0-5"})
	if w.Code != 206 || w.Body.Len() != 6 || !strings.HasPrefix(w.Header().Get("Content-Range"), "bytes 0-5/") {
		t.Errorf("Range: %d %v", w.Code, w.Header())
	}
}

// Валидаторы стабильны для одной страницы и соли, у разных установок разные, но по виду как у nginx.
func TestValidatorsDependOnSalt(t *testing.T) {
	re := regexp.MustCompile(`^"[0-9a-f]+-[0-9a-f]+"$`)
	setup()
	a1 := probe("GET", "/", nil).Header()
	a2 := probe("GET", "/", nil).Header()
	if a1.Get("ETag") != a2.Get("ETag") || a1.Get("Last-Modified") != a2.Get("Last-Modified") {
		t.Fatal("валидаторы одной страницы нестабильны")
	}
	SetSalt("salt-b")
	b := probe("GET", "/", nil).Header()
	if b.Get("ETag") == a1.Get("ETag") || b.Get("Last-Modified") == a1.Get("Last-Modified") {
		t.Fatal("у разных соли и одной страницы валидаторы совпали")
	}
	if !re.MatchString(a1.Get("ETag")) {
		t.Fatalf("ETag не в виде nginx: %s", a1.Get("ETag"))
	}
	lm, err := http.ParseTime(a1.Get("Last-Modified"))
	if err != nil || lm.Before(time.Date(2023, 3, 1, 0, 0, 0, 0, time.UTC)) || lm.After(time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("Last-Modified вне разумных пределов: %v %v", lm, err)
	}
	SetSalt("salt-a")
}

// Страница меняется на лету: следующий запрос видит новую.
func TestPageChangesWithoutRestart(t *testing.T) {
	setup()
	e1 := probe("GET", "/", nil).Header().Get("ETag")
	SetPage("<html>другая</html>")
	w := probe("GET", "/", nil)
	if w.Body.String() != "<html>другая</html>" || w.Header().Get("ETag") == e1 {
		t.Fatalf("страница не обновилась: %q %v", w.Body.String(), w.Header())
	}
	setup()
}

// Локальный слушатель (его проксирует Hysteria) отвечает тем же, что обработчик напрямую, то есть так же, как сайт на домене.
func TestLocalListenerMatchesHandler(t *testing.T) {
	setup()
	StartLocal()
	u := LocalURL()
	if u == "" {
		t.Skip("порт слушателя занят в этой среде")
	}
	for _, p := range []string{"/", "/favicon.ico", "/robots.txt"} {
		resp, err := http.Get(u + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		w := probe("GET", p, nil)
		if resp.StatusCode != w.Code || string(b) != w.Body.String() {
			t.Errorf("%s: слушатель %d, обработчик %d", p, resp.StatusCode, w.Code)
		}
		for _, k := range []string{"Server", "Content-Type", "ETag", "Last-Modified", "Content-Length"} {
			if resp.Header.Get(k) != w.Header().Get(k) {
				t.Errorf("%s: заголовок %s различается: %q и %q", p, k, resp.Header.Get(k), w.Header().Get(k))
			}
		}
	}
}

// Неверный Range: страница ошибки nginx (text/html), без заголовка nosniff от Go.
func TestRangeNotSatisfiable(t *testing.T) {
	setup()
	w := probe("GET", "/", map[string]string{"Range": "bytes=99999-"})
	if w.Code != 416 || w.Header().Get("Content-Type") != "text/html" || w.Header().Get("X-Content-Type-Options") != "" || w.Header().Get("Server") != "nginx" {
		t.Fatalf("416: %d %v", w.Code, w.Header())
	}
	if w.Body.String() != rangeBody || w.Header().Get("Content-Length") != strconv.Itoa(len(rangeBody)) {
		t.Fatalf("416: тело %q", w.Body.String())
	}
}

// «OPTIONS *» не должен обрабатываться встроенным обработчиком net/http (200 без Server): с DisableGeneralOptionsHandler он
// доходит до нашего обработчика и получает 405 как любой другой не-GET.
func TestOptionsStarGoesToHandler(t *testing.T) {
	setup()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("нет локального сокета")
	}
	srv := &http.Server{Handler: Handler(), ReadHeaderTimeout: 5 * time.Second, DisableGeneralOptionsHandler: true}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "OPTIONS * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(c)
	s := string(b)
	if !strings.Contains(s, "405") || !strings.Contains(strings.ToLower(s), "server: nginx") {
		t.Fatalf("OPTIONS *: %q", s)
	}
}
