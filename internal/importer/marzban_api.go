package importer

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Ограничения запросов к API Marzban.
const (
	apiUsersPage    = 100
	apiMaxPages     = MaxUsers/apiUsersPage + 2
	apiMaxResponse  = 4 << 20 // один ответ (страница)
	apiMaxRedirects = 3
	maxTokenLen     = 4096
)

// apiTimeout – сколько всего можно читать Marzban по API: вызывающий код держит блокировку импорта.
var apiTimeout = 3 * time.Minute

// apiRequestTimeout – срок одного запроса.
var apiRequestTimeout = 30 * time.Second

// apiTransportHook нужен тестам, чтобы подставить свои доверенные сертификаты.
var apiTransportHook func(*http.Transport)

// APIAuth – доступ к API Marzban: готовый токен или логин с паролем администратора.
// Значения живут только в памяти на время запуска; в отчёт, логи и ошибки не попадают.
type APIAuth struct {
	Token, Username, Password string
}

// Empty сообщает, что ни токена, ни логина с паролем нет.
func (a APIAuth) Empty() bool { return a.Token == "" && (a.Username == "" || a.Password == "") }

// Clear стирает значения из памяти, насколько это возможно для строк Go (заменой ссылок).
func (a *APIAuth) Clear() { *a = APIAuth{} }

// loopbackHost – localhost или адрес петли: только к ним можно ходить по http.
func loopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	return ip != nil && ip.IsLoopback()
}

// ParseAPIURL проверяет адрес Marzban, введённый пользователем: https (http только для localhost), без логина в адресе,
// без параметров, с портом в допустимых пределах.
func ParseAPIURL(raw string) (*url.URL, error) {
	bad := errors.New("адрес Marzban указан неверно: нужен вид https://panel.example.com:8000")
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 512 {
		return nil, bad
	}
	for _, r := range raw {
		if r <= 0x20 || r >= 0x7f {
			return nil, bad
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return nil, bad
	}
	if u.User != nil {
		return nil, errors.New("адрес Marzban не должен содержать логин и пароль")
	}
	if u.RawQuery != "" || u.Fragment != "" || strings.Contains(u.Path, "..") {
		return nil, bad
	}
	host := u.Hostname()
	if net.ParseIP(host) == nil && (!hostRe.MatchString(host) || strings.Contains(host, "*")) {
		return nil, bad
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, bad
		}
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopbackHost(host) {
			return nil, errors.New("к Marzban можно подключаться только по https; http разрешён только для localhost")
		}
	default:
		return nil, bad
	}
	p := path.Clean("/" + strings.Trim(u.Path, "/"))
	p = strings.TrimSuffix(p, "/dashboard") // адрес страницы входа вместо адреса API
	u.Path, u.RawPath = strings.TrimRight(p, "/"), ""
	return u, nil
}

type apiClient struct {
	base  *url.URL
	hc    *http.Client
	token string
	read  int // сколько байт ответов прочитано всего
}

// apiError – ответ Marzban с кодом ошибки (текст ответа наружу не отдаётся: в нём может быть что угодно).
type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func newAPIClient(base *url.URL) *apiClient {
	tr := &http.Transport{
		Proxy:                  nil, // запросы идут напрямую по указанному адресу
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    15 * time.Second,
		ResponseHeaderTimeout:  apiRequestTimeout,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	if apiTransportHook != nil {
		apiTransportHook(tr)
	}
	return &apiClient{base: base, hc: &http.Client{
		Transport: tr,
		Timeout:   apiRequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Только в пределах того же адреса и без понижения до http: токен не уходит на чужой хост.
			if len(via) > apiMaxRedirects || req.URL.Host != base.Host || req.URL.Scheme != base.Scheme {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}}
}

func (a *apiClient) endpoint(p, query string) string {
	u := *a.base
	u.Path = strings.TrimRight(a.base.Path, "/") + p
	u.RawQuery = query
	return u.String()
}

// do выполняет запрос и возвращает тело ответа (не больше limit байт).
func (a *apiClient) do(ctx context.Context, method, p, query string, form url.Values, limit int) ([]byte, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, a.endpoint(p, query), body)
	if err != nil {
		return nil, errors.New("адрес Marzban указан неверно")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return nil, apiNetErr(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, apiStatusErr(resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, apiNetErr(ctx, err)
	}
	if len(raw) > limit {
		return nil, errors.New("ответ Marzban слишком большой, импорт отклонён")
	}
	if a.read += len(raw); a.read > maxReadBytes {
		return nil, fmt.Errorf("Marzban отдал больше %d МБ данных, импорт отклонён", maxReadBytes>>20)
	}
	return raw, nil
}

// apiNetErr превращает сетевую ошибку в понятное сообщение без адреса и без деталей, которые могли бы содержать секреты.
func apiNetErr(ctx context.Context, err error) error {
	var (
		cv *tls.CertificateVerificationError
		ua x509.UnknownAuthorityError
		ci x509.CertificateInvalidError
		he x509.HostnameError
	)
	switch {
	case ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded):
		return errors.New("Marzban не ответил вовремя")
	case errors.As(err, &cv), errors.As(err, &ua), errors.As(err, &ci), errors.As(err, &he):
		return errors.New("сертификат сервера Marzban не прошёл проверку: нужен действующий сертификат на имя из адреса")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return errors.New("Marzban не ответил вовремя")
	}
	return errors.New("не удалось подключиться к Marzban: проверьте адрес и доступность")
}

func apiStatusErr(code int) error {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return &apiError{code, "Marzban перенаправляет на другой адрес: укажите конечный адрес (например, https://panel.example.com:8000)"}
	case http.StatusUnauthorized:
		return &apiError{code, "Marzban отклонил логин, пароль или токен"}
	case http.StatusForbidden:
		return &apiError{code, "у этой учётной записи Marzban нет нужных прав"}
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return &apiError{code, "по этому адресу нет API Marzban: проверьте адрес"}
	case http.StatusTooManyRequests:
		return &apiError{code, "Marzban просит подождать: слишком много запросов"}
	}
	return &apiError{code, fmt.Sprintf("Marzban ответил ошибкой %d", code)}
}

func validToken(t string) bool {
	if t == "" || len(t) > maxTokenLen {
		return false
	}
	for i := 0; i < len(t); i++ {
		if t[i] < 0x21 || t[i] > 0x7e {
			return false
		}
	}
	return true
}

// login меняет логин и пароль администратора на токен доступа.
func (a *apiClient) login(ctx context.Context, user, pass string) error {
	if len(user) > 256 || len(pass) > 1024 || user == "" || pass == "" {
		return errors.New("логин или пароль Marzban указаны неверно")
	}
	raw, err := a.do(ctx, http.MethodPost, "/api/admin/token", "", url.Values{"username": {user}, "password": {pass}}, 1<<20)
	if err != nil {
		return err
	}
	var r struct {
		Token string `json:"access_token"`
	}
	if json.Unmarshal(raw, &r) != nil || !validToken(r.Token) {
		return errors.New("Marzban не выдал токен: проверьте адрес и учётную запись")
	}
	a.token = r.Token
	return nil
}

// ReadMarzbanAPI читает пользователей Marzban через его API (GET /api/users) и, если у учётной записи хватает прав,
// подключения из настроек Xray (GET /api/core/config). Адрес проверяется ParseAPIURL. Ничего не изменяется в Marzban:
// единственный не-GET запрос – получение токена по логину и паролю.
func ReadMarzbanAPI(ctx context.Context, rawURL string, auth APIAuth) (*Data, error) {
	base, err := ParseAPIURL(rawURL)
	if err != nil {
		return nil, err
	}
	if auth.Token != "" && !validToken(auth.Token) {
		return nil, errors.New("токен указан неверно")
	}
	if auth.Empty() {
		return nil, errors.New("укажите токен или логин и пароль администратора Marzban")
	}
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	a := newAPIClient(base)
	if auth.Token != "" {
		a.token = auth.Token
	} else if err := a.login(ctx, auth.Username, auth.Password); err != nil {
		return nil, err
	}

	data := &Data{Source: SourceMarzban}
	seen := map[string]bool{}
	total := -1
	got, dropped := 0, 0 // получено разных записей; из них отброшено при разборе
	for page := 0; page < apiMaxPages; page++ {
		raw, err := a.do(ctx, http.MethodGet, "/api/users", fmt.Sprintf("offset=%d&limit=%d", page*apiUsersPage, apiUsersPage), nil, apiMaxResponse)
		if err != nil {
			return nil, err
		}
		var r struct {
			Users []map[string]any `json:"users"`
			Total *int64           `json:"total"`
		}
		if json.Unmarshal(raw, &r) != nil || (r.Users == nil && r.Total == nil) {
			return nil, errors.New("ответ Marzban не похож на список пользователей: проверьте адрес")
		}
		if r.Total != nil {
			total = int(min64(*r.Total, int64(MaxUsers)+1))
		}
		if total > MaxUsers {
			return nil, fmt.Errorf("пользователей больше %d", MaxUsers)
		}
		repeats := 0
		for _, ru := range r.Users {
			u, ok := marzbanUser(ru, apiProxies(ru))
			if !ok {
				got++
				dropped++
				continue
			}
			if k := strings.ToLower(u.Name); !seen[k] {
				seen[k] = true
				got++
				data.Users = append(data.Users, u)
			} else {
				repeats++
			}
		}
		if repeats > 0 && repeats == len(r.Users) {
			break // сервер повторяет уже полученную страницу (offset игнорируется)
		}
		if len(r.Users) < apiUsersPage || (total >= 0 && (page+1)*apiUsersPage >= total) {
			break
		}
		if len(data.Users) > MaxUsers {
			return nil, fmt.Errorf("пользователей больше %d", MaxUsers)
		}
	}

	if total > got {
		data.Notes = append(data.Notes, fmt.Sprintf("Прочитано %d из %d пользователей: Marzban отдал не все страницы. Перенос неполный, остальных добавьте вручную или повторите импорт.", len(data.Users), total))
	} else if total > len(data.Users) {
		data.Notes = append(data.Notes, fmt.Sprintf("Прочитано %d из %d пользователей: %d пропущено при разборе (например, некорректное имя). Добавьте их вручную.", len(data.Users), total, dropped))
	}
	data.Notes = append(data.Notes,
		"Ссылка подписки Marzban строится из токена и не хранится в базе: после переноса у пользователей будут новые ссылки.",
		"Администраторы Marzban и их права не переносятся; ограничения по устройствам в Marzban нет.")
	a.readInbounds(ctx, data)
	return data, nil
}

// apiProxies достаёт учётные данные пользователя из поля proxies ответа API.
func apiProxies(u map[string]any) []marzbanProxy {
	m, _ := u["proxies"].(map[string]any)
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	var out []marzbanProxy
	for _, k := range names {
		v, _ := m[k].(map[string]any)
		p := marzbanProxy{uuid: strings.ToLower(str(v, "id")), password: str(v, "password"), flow: str(v, "flow")}
		if strings.ToLower(k) != "trojan" {
			p.password = ""
		}
		out = append(out, p)
	}
	return out
}

// readInbounds берёт подключения из настроек Xray, которые отдаёт Marzban администратору с полными правами.
// Без них (нет прав, старая версия) остаются только теги подключений для справки.
func (a *apiClient) readInbounds(ctx context.Context, data *Data) {
	raw, err := a.do(ctx, http.MethodGet, "/api/core/config", "", nil, MaxConfigSize)
	if err == nil {
		if cfg, perr := parseXrayConfig(bytes.TrimSpace(raw)); perr == nil {
			data.WithConfig(cfg)
			return
		}
		data.Notes = append(data.Notes, "Настройки Xray из Marzban не разобраны: подключения не перенесены, создайте их в Kitsune или укажите config.json.")
	} else if ae := (*apiError)(nil); errors.As(err, &ae) && (ae.status == http.StatusForbidden || ae.status == http.StatusNotFound || ae.status == http.StatusMethodNotAllowed) {
		data.Notes = append(data.Notes, "У этой учётной записи Marzban нет прав на чтение настроек Xray: подключения не перенесены. Войдите администратором с полными правами или укажите config.json.")
	} else {
		data.Notes = append(data.Notes, "Не удалось прочитать настройки Xray из Marzban: подключения не перенесены.")
	}
	raw, err = a.do(ctx, http.MethodGet, "/api/inbounds", "", nil, 1<<20)
	if err != nil {
		return
	}
	var groups map[string][]map[string]any
	if json.Unmarshal(raw, &groups) != nil {
		return
	}
	names := make([]string, 0, len(groups))
	for k := range groups {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		for _, ib := range groups[k] {
			if len(data.Inbounds) >= MaxInbounds {
				return
			}
			if t := cleanText(toStr(ib["tag"]), 60); t != "" {
				data.Inbounds = append(data.Inbounds, SrcInbound{Name: t, SkipReason: "настройки подключения Marzban не получены по API: создайте подключение в Kitsune или укажите config.json Xray"})
			}
		}
	}
}
