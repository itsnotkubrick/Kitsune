package servertest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Внешние тесты ходят к сторонним сервисам и запускаются только после согласия пользователя:
//   - ipinfo.io: узнаёт публичный адрес сервера, страну, сеть и организацию (сервис видит только адрес, с которого идёт запрос);
//   - сервис списков: отдаёт файл со списком адресов, проверка адреса идёт локально, наружу ничего не уходит;
//   - Globalping (api.globalping.io): ping с зондов другого региона до адреса сервера (сервису уходят адрес сервера и порт).
// Адреса сервисов зашиты в код, пользовательского ввода в запросах нет.

// Net – адреса сервисов и HTTP-клиент (в тестах подменяются).
type Net struct {
	HTTP          *http.Client
	IPInfoURL     string
	ListURL       string // агрегат: адреса, сведённые в подсети (намёк, не приговор)
	ExactURL      string // точные адреса из списка
	GlobalpingURL string
	Port          int           // порт для TCP-проверки; 0 – ICMP ping
	GeoTargets    []GeoTarget   // nil – DefaultGeoTargets
	SpeedTargets  []SpeedTarget // nil – DefaultSpeedTargets
}

// DefaultNet – настоящие сервисы.
func DefaultNet() Net {
	return Net{
		HTTP:          &http.Client{Timeout: 20 * time.Second},
		IPInfoURL:     "https://ipinfo.io/json",
		ListURL:       listsBase + "allyouneed.lst",
		ExactURL:      listsBase + "ip.lst",
		GlobalpingURL: "https://api.globalping.io/v1/measurements",
	}
}

// listsBase – адрес сервиса списков.
var listsBase = "https://" + "anti" + "filter" + ".download/list/"

const (
	userAgent    = "kitsune-servertest/1.0"
	maxListBytes = 8 << 20
	maxJSONBytes = 1 << 20
	pollInterval = 700 * time.Millisecond // Globalping просит не чаще раза в 500 мс
	pollDeadline = 25 * time.Second
	probeLimit   = 5 // зондов в одном измерении
)

type ipInfo struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Org      string `json:"org"` // «AS12345 Название»
}

// state хранит результат запроса к ipinfo: он нужен нескольким тестам, а запрашивается один раз за прогон.
type state struct {
	n    Net
	once sync.Once
	info ipInfo
	err  error
}

func (s *state) get(ctx context.Context) (ipInfo, error) {
	s.once.Do(func() { s.err = getJSON(ctx, s.n.HTTP, s.n.IPInfoURL, &s.info) })
	if s.err == nil && net.ParseIP(s.info.IP) == nil {
		return s.info, fmt.Errorf("unexpected answer: no address")
	}
	return s.info, s.err
}

func getJSON(ctx context.Context, c *http.Client, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxJSONBytes)).Decode(v)
}

// External – тесты с внешними сервисами (только после согласия пользователя).
func External(n Net) []Test {
	s := &state{n: n}
	return []Test{
		{ID: "region", Group: "network", External: true, Timeout: 15 * time.Second, Run: func(ctx context.Context, l Lang) Result { return testRegion(ctx, l, s) }},
		{ID: "reputation", Group: "reach", External: true, Timeout: 30 * time.Second, Run: func(ctx context.Context, l Lang) Result { return testReputation(ctx, l, s) }},
		{ID: "reach_region", Group: "reach", External: true, Timeout: 45 * time.Second, Run: func(ctx context.Context, l Lang) Result { return testReachRegion(ctx, l, s) }},
	}
}

// ---- регион и поставщик ----

var hostingWords = []string{"hosting", "cloud", "server", "datacenter", "data center", "vps", "colo", "dedicated", "ovh", "hetzner", "digitalocean", "vultr", "linode", "contabo", "scaleway", "selectel", "timeweb", "aeza", "amazon", "google", "microsoft", "oracle", "choopa", "leaseweb", "m247", "ionos", "kamatera"}

// looksLikeHosting – оценка по названию организации: это сеть хостера или дата-центра.
func looksLikeHosting(org string) bool {
	o := strings.ToLower(org)
	for _, w := range hostingWords {
		if strings.Contains(o, w) {
			return true
		}
	}
	return false
}

func testRegion(ctx context.Context, l Lang, s *state) Result {
	title := L(l, "Регион и поставщик", "Region and provider")
	info, err := s.get(ctx)
	if err != nil {
		return Result{ID: "region", Group: "network", Level: Warn, Title: title, Detail: err.Error(), Hint: L(l, "Не удалось узнать публичный адрес и регион: сервис недоступен.", "Could not get the public address and region: the service is unavailable.")}
	}
	parts := []string{info.IP}
	for _, v := range []string{info.Country, info.Region, info.City, info.Org} {
		if v != "" {
			parts = append(parts, v)
		}
	}
	detail := strings.Join(parts, ", ")
	if looksLikeHosting(info.Org) {
		detail += " (" + L(l, "сеть хостера или дата-центра", "hosting or data-center network") + ")"
	}
	return Result{ID: "region", Group: "network", Level: Info, Title: title, Detail: detail}
}

// ---- репутация адреса ----

// ipInList проверяет, входит ли адрес в список строк «адрес» или «подсеть/маска». Неразбираемые строки пропускаются.
func ipInList(ip net.IP, r io.Reader) (bool, string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if strings.Contains(s, "/") {
			if _, n, err := net.ParseCIDR(s); err == nil && n.Contains(ip) {
				return true, s, nil
			}
		} else if p := net.ParseIP(s); p != nil && p.Equal(ip) {
			return true, s, nil
		}
	}
	return false, "", sc.Err()
}

// checkList скачивает список по адресу url и проверяет в нём адрес ip.
func checkList(ctx context.Context, c *http.Client, url string, ip net.IP) (bool, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return ipInList(ip, io.LimitReader(resp.Body, maxListBytes))
}

// testReputation: точный адрес в списке – «не подходит»; адрес только в агрегированной подсети (рядом есть адреса из списка) –
// предупреждение: сам адрес не обязательно в списке, это подтверждает проверка доступности ниже.
func testReputation(ctx context.Context, l Lang, s *state) Result {
	title := L(l, "Репутация адреса", "Address reputation")
	info, err := s.get(ctx)
	if err != nil {
		return Result{ID: "reputation", Group: "reach", Level: Skip, Title: title, Detail: err.Error(), Hint: L(l, "Не удалось узнать адрес сервера.", "Could not determine the server address.")}
	}
	ip := net.ParseIP(info.IP)
	src := "lists"
	failed := func(err error) Result {
		return Result{ID: "reputation", Group: "reach", Level: Warn, Title: title, Detail: err.Error(), Hint: L(l, "Не удалось скачать список.", "Could not download the list.")}
	}
	if s.n.ExactURL != "" {
		hit, _, err := checkList(ctx, s.n.HTTP, s.n.ExactURL, ip)
		if err != nil {
			return failed(err)
		}
		if hit {
			return Result{ID: "reputation", Group: "reach", Level: Bad, Title: title, Detail: fmt.Sprintf("%s: %s (%s)", info.IP, L(l, "точный адрес найден в списке", "the exact address is in the list"), src),
				Hint: L(l, "Адрес в списке: из некоторых регионов он, скорее всего, недоступен. Лучше взять другой адрес или хостера.",
					"The address is listed: it is most likely unreachable from some regions. Better take another address or host.")}
		}
	}
	hit, by, err := checkList(ctx, s.n.HTTP, s.n.ListURL, ip)
	if err != nil {
		return failed(err)
	}
	if hit {
		return Result{ID: "reputation", Group: "reach", Level: Warn, Title: title, Detail: fmt.Sprintf("%s: %s %s (%s)", info.IP, L(l, "сам адрес не найден, но подсеть в списке:", "the address itself is not listed, but its subnet is:"), by, src),
			Hint: L(l, "В вашей подсети есть адреса из списка. Сам сервер это не затрагивает; решает проверка доступности из других регионов (в меню kit пункты 8 и 9; лучше по TCP с открытым портом: kit test --external --port 443).",
				"There are listed addresses in your subnet. This does not affect your server by itself; the reachability check from other regions decides (kit menu items 8 and 9; better over TCP with an open port: kit test --external --port 443).")}
	}
	return Result{ID: "reputation", Group: "reach", Level: OK, Title: title, Detail: fmt.Sprintf("%s: %s (%s)", info.IP, L(l, "в списках не найден", "not in the lists"), src)}
}

// ---- доступность из других регионов (Globalping) ----

type gpStats struct {
	Min  float64 `json:"min"`
	Avg  float64 `json:"avg"`
	Max  float64 `json:"max"`
	Rcv  int     `json:"rcv"`
	Loss float64 `json:"loss"`
}

type gpProbe struct {
	Network string `json:"network"`
	City    string `json:"city"`
}

type gpEntry struct {
	Probe  gpProbe `json:"probe"`
	Result struct {
		Status string   `json:"status"`
		Stats  *gpStats `json:"stats"`
	} `json:"result"`
}

type gpMeasurement struct {
	Status  string    `json:"status"`
	Results []gpEntry `json:"results"`
}

// judgeReach оценивает ответы зондов: все ответили – ok, часть – warn, никто – для ICMP warn (ответы могут быть закрыты), для TCP bad.
func judgeReach(res []gpEntry, tcp bool, l Lang) (Level, string, string) {
	n, ok := len(res), 0
	var avgs []float64
	var silent []string // сети зондов, которые не получили ответа
	for _, e := range res {
		if e.Result.Stats != nil && e.Result.Stats.Rcv > 0 {
			ok++
			avgs = append(avgs, e.Result.Stats.Avg)
		} else if nw := strings.TrimSpace(e.Probe.Network); nw != "" {
			silent = append(silent, nw)
		}
	}
	if n == 0 {
		return Warn, L(l, "нет ответов от зондов", "no answers from the probes"), L(l, "Сервис не вернул результатов: повторите позже.", "The service returned no results: try again later.")
	}
	sort.Float64s(avgs)
	detail := fmt.Sprintf("%d/%d %s", ok, n, L(l, "зондов получили ответ", "probes got an answer"))
	if ok > 0 {
		detail += fmt.Sprintf(", %s %.0f %s", L(l, "медиана", "median"), avgs[len(avgs)/2], L(l, "мс", "ms"))
	}
	if len(silent) > 0 && ok < n {
		detail += fmt.Sprintf("; %s: %s", L(l, "без ответа", "no answer"), strings.Join(silent, ", "))
	}
	switch {
	case ok*5 >= n*4: // 80% и больше: один случайный зонд из пяти не отвечает часто, это не отказ
		return OK, detail, ""
	case ok == 0 && tcp:
		return Bad, detail, L(l, "Порт не отвечает из других регионов: проверьте файрвол и доступность адреса.", "The port does not answer from other regions: check the firewall and whether the address is reachable.")
	case ok == 0:
		return Warn, detail, L(l, "Ни один зонд не получил ответ на ping. Многие хостеры закрывают ICMP, поэтому это не обязательно проблема: проверьте ещё раз с открытым портом (kit test --external --port 443).", "No probe got a ping answer. Many hosts disable ICMP, so this is not necessarily a problem: check again with an open port (kit test --external --port 443).")
	}
	return Warn, detail, L(l, "Часть сетей не достаёт до сервера: возможны ограничения у отдельных провайдеров.", "Some networks cannot reach the server: there may be restrictions at some providers.")
}

func testReachRegion(ctx context.Context, l Lang, s *state) Result {
	title := L(l, "Доступность из других регионов", "Reachability from other regions")
	info, err := s.get(ctx)
	if err != nil {
		return Result{ID: "reach_region", Group: "reach", Level: Skip, Title: title, Detail: err.Error(), Hint: L(l, "Не удалось узнать адрес сервера.", "Could not determine the server address.")}
	}
	opts := map[string]any{"packets": 3}
	if s.n.Port > 0 {
		opts["protocol"], opts["port"] = "TCP", s.n.Port
	}
	body, _ := json.Marshal(map[string]any{"type": "ping", "target": info.IP, "locations": []map[string]string{{"country": "RU"}}, "limit": probeLimit, "measurementOptions": opts})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.n.GlobalpingURL, bytes.NewReader(body))
	if err != nil {
		return Result{ID: "reach_region", Group: "reach", Level: Warn, Title: title, Detail: err.Error()}
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.n.HTTP.Do(req)
	if err != nil {
		return Result{ID: "reach_region", Group: "reach", Level: Warn, Title: title, Detail: err.Error(), Hint: L(l, "Сервис проверки недоступен.", "The checking service is unavailable.")}
	}
	var made struct {
		ID string `json:"id"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, maxJSONBytes)).Decode(&made)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK || err != nil || made.ID == "" {
		return Result{ID: "reach_region", Group: "reach", Level: Warn, Title: title, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode),
			Hint: L(l, "Сервис проверки не принял запрос (возможно, превышен лимит 250 проверок в час с этого адреса).", "The checking service rejected the request (the limit of 250 checks per hour for this address may be exceeded).")}
	}
	end := time.Now().Add(pollDeadline)
	var m gpMeasurement
	for {
		select {
		case <-ctx.Done():
			return Result{ID: "reach_region", Group: "reach", Level: Warn, Title: title, Detail: ctx.Err().Error()}
		case <-time.After(pollInterval):
		}
		m = gpMeasurement{}
		if err := getJSON(ctx, s.n.HTTP, strings.TrimRight(s.n.GlobalpingURL, "/")+"/"+made.ID, &m); err != nil {
			return Result{ID: "reach_region", Group: "reach", Level: Warn, Title: title, Detail: err.Error()}
		}
		if m.Status == "finished" || time.Now().After(end) {
			break
		}
	}
	lv, detail, hint := judgeReach(m.Results, s.n.Port > 0, l)
	return Result{ID: "reach_region", Group: "reach", Level: lv, Title: title, Detail: detail, Hint: hint}
}
