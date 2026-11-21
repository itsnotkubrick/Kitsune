// Package site – общий обработчик «обычного сайта»: им отвечают и self-steal (TCP), и Hysteria2 (HTTP/3, через локальный
// слушатель), поэтому на одном домене по обоим транспортам посторонний получает одинаковые ответы, как от статического
// сайта на nginx (без версии): страница на «/», страница ошибки на остальных путях, 405 на не-GET/HEAD, условные запросы и Range.
package site

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"kitsune/internal/stub"
)

// LocalAddr – адрес локального слушателя для Hysteria (masquerade type=proxy). Слушает только 127.0.0.1.
const LocalAddr = "127.0.0.1:10398"

var (
	page atomic.Pointer[string] // текущая страница; меняется на лету
	salt atomic.Pointer[string] // соль установки: от неё зависят ETag и Last-Modified

	localMu sync.Mutex
	localOn bool
)

// SetPage делает страницу текущей для всех слушателей.
func SetPage(html string) { page.Store(&html) }

// SetSalt задаёт соль установки (валидаторы страницы у разных серверов с одной страницей различаются).
func SetSalt(s string) { salt.Store(&s) }

func current() string {
	if p := page.Load(); p != nil {
		return *p
	}
	return stub.HTML(stub.DefaultID)
}

// validators считает Last-Modified и ETag в виде nginx: ETag – «время-размер» в шестнадцатеричном виде. Время выводится из
// содержимого и соли в пределах примерно трёх лет, поэтому у одной и той же страницы на разных серверах оно разное.
func validators(body string) (time.Time, string) {
	s := ""
	if p := salt.Load(); p != nil {
		s = *p
	}
	sum := sha256.Sum256([]byte("site|" + s + "|" + body))
	const base = 1677628800 // 2023-03-01
	const span = 94608000   // три года
	ts := int64(base) + int64(binary.BigEndian.Uint32(sum[:4]))%span
	return time.Unix(ts, 0).UTC(), fmt.Sprintf(`"%x-%x"`, ts, len(body))
}

const (
	notFoundBody   = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
	notAllowedBody = "<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n<center><h1>405 Not Allowed</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
)

// NotFoundBody – страница 404 из nginx (версия скрыта); её же отдают панель и сайт-заглушка.
const NotFoundBody = notFoundBody

const rangeBody = "<html>\r\n<head><title>416 Requested Range Not Satisfiable</title></head>\r\n<body>\r\n<center><h1>416 Requested Range Not Satisfiable</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"

// fixRange заменяет ответ 416, который http.ServeContent пишет как text/plain с nosniff (у Go), страницей nginx.
type fixRange struct {
	http.ResponseWriter
	swallow bool
}

func (w *fixRange) WriteHeader(code int) {
	if code == http.StatusRequestedRangeNotSatisfiable {
		h := w.Header()
		h.Del("X-Content-Type-Options")
		h.Set("Content-Type", "text/html")
		h.Set("Content-Length", strconv.Itoa(len(rangeBody)))
		w.swallow = true
		w.ResponseWriter.WriteHeader(code)
		_, _ = w.ResponseWriter.Write([]byte(rangeBody))
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *fixRange) Write(b []byte) (int, error) {
	if w.swallow {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

func errorPage(w http.ResponseWriter, r *http.Request, code int, body string) {
	h := w.Header()
	h.Set("Content-Type", "text/html")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(code)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(body))
	}
}

// Handler отвечает как статический сайт на nginx.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			errorPage(w, r, http.StatusMethodNotAllowed, notAllowedBody)
			return
		}
		// «//» и «/?x=1» отдают ту же страницу, что «/» (nginx склеивает слэши и не смотрит на строку запроса).
		if p := r.URL.Path; strings.Trim(p, "/") != "" && p != "/index.html" {
			errorPage(w, r, http.StatusNotFound, notFoundBody)
			return
		}
		body := current()
		mod, etag := validators(body)
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("ETag", etag)
		http.ServeContent(&fixRange{ResponseWriter: w}, r, "", mod, strings.NewReader(body))
	})
}

// StartLocal запускает локальный слушатель (один раз). Hysteria проксирует на него ответы постороннему. Если порт занят,
// слушатель не запускается, и конфиг Hysteria остаётся со встроенной страницей.
func StartLocal() {
	localMu.Lock()
	defer localMu.Unlock()
	if localOn {
		return
	}
	ln, err := net.Listen("tcp", LocalAddr)
	if err != nil {
		return
	}
	localOn = true
	srv := &http.Server{Handler: Handler(), ReadHeaderTimeout: 10 * time.Second, DisableGeneralOptionsHandler: true}
	go func() { _ = srv.Serve(ln) }()
}

// LocalURL – адрес локального слушателя для конфига Hysteria (пусто, если слушатель не запущен).
func LocalURL() string {
	localMu.Lock()
	defer localMu.Unlock()
	if !localOn {
		return ""
	}
	return "http://" + LocalAddr
}
