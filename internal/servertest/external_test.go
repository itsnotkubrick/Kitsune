package servertest

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// fake поднимает три «сервиса» на одном сервере: ipinfo, сервис списков и Globalping.
type fake struct {
	ip, list, exact, gp string // ответ ipinfo (адрес), агрегированный список, точный список, JSON результатов Globalping
	ipCalls             atomic.Int32
	gpBody              atomic.Value // тело последнего POST
}

func (f *fake) net(t *testing.T) Net {
	mux := http.NewServeMux()
	mux.HandleFunc("/ipinfo", func(w http.ResponseWriter, r *http.Request) {
		f.ipCalls.Add(1)
		if r.Header.Get("User-Agent") == "" {
			t.Error("запрос без User-Agent")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"ip": f.ip, "country": "DE", "city": "Falkenstein", "org": "AS24940 Hetzner Online GmbH"})
	})
	mux.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(f.list)) })
	mux.HandleFunc("/exact", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(f.exact)) })
	mux.HandleFunc("/gp", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.gpBody.Store(string(b))
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"m1","probesCount":2}`))
	})
	mux.HandleFunc("/gp/m1", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(f.gp)) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return Net{HTTP: srv.Client(), IPInfoURL: srv.URL + "/ipinfo", ListURL: srv.URL + "/list", ExactURL: srv.URL + "/exact", GlobalpingURL: srv.URL + "/gp"}
}

const gpAllOK = `{"status":"finished","results":[{"probe":{"network":"Selectel"},"result":{"status":"finished","stats":{"avg":10,"rcv":3,"loss":0}}},{"probe":{"network":"Timeweb"},"result":{"status":"finished","stats":{"avg":14,"rcv":3,"loss":0}}}]}`
const gpNone = `{"status":"finished","results":[{"probe":{"network":"Selectel"},"result":{"status":"finished","stats":{"avg":0,"rcv":0,"loss":100}}},{"probe":{"network":"Timeweb"},"result":{"status":"finished","stats":{"rcv":0,"loss":100}}}]}`
const gpHalf = `{"status":"finished","results":[{"probe":{"network":"Selectel"},"result":{"stats":{"avg":10,"rcv":3}}},{"probe":{"network":"Timeweb"},"result":{"stats":{"rcv":0}}}]}`

func byID(rep Report) map[string]Result {
	m := map[string]Result{}
	for _, r := range rep.Results {
		m[r.ID] = r
	}
	return m
}

func TestExternalHappyPath(t *testing.T) {
	f := &fake{ip: "203.0.113.9", list: "198.51.100.0/24\n192.0.2.7\n", gp: gpAllOK}
	rep := Run(context.Background(), External(f.net(t)), EN, nil)
	m := byID(rep)
	if m["region"].Level != Info || !strings.Contains(m["region"].Detail, "203.0.113.9") || !strings.Contains(m["region"].Detail, "hosting") {
		t.Errorf("region: %+v", m["region"])
	}
	if m["reputation"].Level != OK || m["reach_region"].Level != OK || !strings.Contains(m["reach_region"].Detail, "2/2") {
		t.Errorf("rkn=%+v reach=%+v", m["reputation"], m["reach_region"])
	}
	if rep.Verdict != "ok" {
		t.Errorf("сводка %s", rep.Verdict)
	}
	if f.ipCalls.Load() != 1 {
		t.Errorf("ipinfo спрашивали %d раз, ожидался один за прогон", f.ipCalls.Load())
	}
	body, _ := f.gpBody.Load().(string)
	if !strings.Contains(body, `"target":"203.0.113.9"`) || !strings.Contains(body, `"country":"RU"`) || strings.Contains(body, "TCP") {
		t.Errorf("запрос к Globalping: %s", body)
	}
}

func TestExternalExactAddressIsBad(t *testing.T) {
	f := &fake{ip: "198.51.100.77", list: "198.51.100.0/24\n", exact: "198.51.100.77\n", gp: gpAllOK}
	rep := Run(context.Background(), External(f.net(t)), RU, nil)
	if r := byID(rep)["reputation"]; r.Level != Bad || !strings.Contains(r.Detail, "точный адрес") {
		t.Fatalf("rkn: %+v", r)
	}
	if rep.Verdict != "bad" {
		t.Fatalf("сводка %s", rep.Verdict)
	}
}

// Адрес только в агрегированной подсети ((в списке соседи)): предупреждение, сводка «с оговорками», а не «не подходит».
func TestExternalSubnetOnlyIsWarning(t *testing.T) {
	f := &fake{ip: "198.51.100.77", list: "# список\n198.51.100.0/24\n", exact: "198.51.100.5\n", gp: gpAllOK}
	rep := Run(context.Background(), External(f.net(t)), EN, nil)
	r := byID(rep)["reputation"]
	if r.Level != Warn || !strings.Contains(r.Detail, "198.51.100.0/24") || !strings.Contains(r.Detail, "not listed") {
		t.Fatalf("rkn: %+v", r)
	}
	if rep.Verdict != "caveats" {
		t.Fatalf("сводка %s", rep.Verdict)
	}
}

func TestExternalReachCases(t *testing.T) {
	for _, c := range []struct {
		name, gp string
		port     int
		want     Level
	}{{"никто по ICMP", gpNone, 0, Warn}, {"никто по TCP", gpNone, 443, Bad}, {"половина", gpHalf, 443, Warn}} {
		f := &fake{ip: "203.0.113.9", list: "", gp: c.gp}
		n := f.net(t)
		n.Port = c.port
		r := byID(Run(context.Background(), External(n), EN, nil))["reach_region"]
		if r.Level != c.want {
			t.Errorf("%s: %s, ожидалось %s (%+v)", c.name, r.Level, c.want, r)
		}
		if c.port > 0 {
			if body, _ := f.gpBody.Load().(string); !strings.Contains(body, `"protocol":"TCP"`) || !strings.Contains(body, `"port":443`) {
				t.Errorf("%s: нет TCP-параметров: %s", c.name, body)
			}
		}
	}
}

func TestExternalServiceDown(t *testing.T) {
	n := Net{HTTP: http.DefaultClient, IPInfoURL: "http://127.0.0.1:1/x", ListURL: "http://127.0.0.1:1/y", GlobalpingURL: "http://127.0.0.1:1/z"}
	rep := Run(context.Background(), External(n), RU, nil)
	m := byID(rep)
	if m["region"].Level != Warn || m["reputation"].Level != Skip || m["reach_region"].Level != Skip {
		t.Fatalf("при недоступных сервисах ожидались warn/skip: %+v", m)
	}
	if rep.Verdict != "caveats" {
		t.Fatalf("сводка %s", rep.Verdict)
	}
}

func TestIPInList(t *testing.T) {
	list := "# комментарий\n\n10.0.0.0/8\n  192.0.2.7  \nмусор\n2001:db8::/32\n"
	for _, c := range []struct {
		ip   string
		want bool
	}{{"10.1.2.3", true}, {"192.0.2.7", true}, {"192.0.2.8", false}, {"2001:db8::5", true}, {"2001:db9::1", false}} {
		got, _, err := ipInList(net.ParseIP(c.ip), strings.NewReader(list))
		if err != nil || got != c.want {
			t.Errorf("%s: %v %v", c.ip, got, err)
		}
	}
}

func TestLooksLikeHosting(t *testing.T) {
	if !looksLikeHosting("AS24940 Hetzner Online GmbH") || !looksLikeHosting("AS9123 TIMEWEB-AS") || looksLikeHosting("AS3320 Deutsche Telekom AG") {
		t.Fatal("определение сети хостера")
	}
}

func TestGeoblock(t *testing.T) {
	status := map[string]int{"/ok": 200, "/api": 401, "/deny": 403, "/legal": 451, "/boom": 503}
	mux := http.NewServeMux()
	for p, c := range status {
		c := c
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(c) })
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()
	n := Net{HTTP: srv.Client()}
	run := func(paths ...string) Result {
		for _, p := range paths {
			n.GeoTargets = append(n.GeoTargets, GeoTarget{Name: strings.TrimPrefix(p, "/"), URL: srv.URL + p})
		}
		defer func() { n.GeoTargets = nil }()
		return testRegional(context.Background(), EN, n)
	}
	if r := run("/ok", "/api"); r.Level != OK || strings.Contains(r.Detail, "refused") {
		t.Errorf("200 и 401 должны быть доступны: %+v", r)
	}
	if r := run("/ok", "/deny", "/legal"); r.Level != Warn || strings.Count(r.Detail, "refused") != 2 {
		t.Errorf("403 и 451 – отказ: %+v", r)
	}
	if r := run("/boom"); r.Level != Warn || !strings.Contains(r.Detail, "refused") && !strings.Contains(r.Detail, "no answer") && !strings.Contains(r.Detail, "reachable") {
		t.Errorf("503: %+v", r)
	}
	n.HTTP = http.DefaultClient
	n.GeoTargets = []GeoTarget{{Name: "dead", URL: "http://127.0.0.1:1/"}}
	if r := testRegional(context.Background(), RU, n); r.Level != Warn || !strings.Contains(r.Detail, "не отвечает") {
		t.Errorf("недоступный сервис: %+v", r)
	}
}

func TestGeoVerdict(t *testing.T) {
	for _, c := range []struct {
		code int
		ok   bool
	}{{200, true}, {302, true}, {401, true}, {404, true}, {403, false}, {451, false}, {500, false}, {0, false}} {
		if ok, _ := geoVerdict(c.code); ok != c.ok {
			t.Errorf("%d: %v", c.code, ok)
		}
	}
}

func TestSpeedMeasuresAndJudges(t *testing.T) {
	body := make([]byte, 2<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/small" {
			_, _ = w.Write(body[:1024])
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	v, err := speedMbit(context.Background(), srv.Client(), SpeedTarget{Name: "x", URL: srv.URL + "/big", Bytes: 2 << 20})
	if err != nil || v <= 0 {
		t.Fatalf("скорость %v, %v", v, err)
	}
	if _, err := speedMbit(context.Background(), srv.Client(), SpeedTarget{Name: "x", URL: srv.URL + "/small", Bytes: 2 << 20}); err == nil {
		t.Fatal("слишком мало данных должно давать ошибку")
	}
	r := testSpeed(context.Background(), EN, Net{HTTP: srv.Client(), SpeedTargets: []SpeedTarget{
		{Name: "w", URL: srv.URL + "/big", Region: "world", Bytes: 2 << 20}, {Name: "r", URL: srv.URL + "/big", Region: "RU", Bytes: 2 << 20}}})
	if r.Level != OK && r.Level != Warn || !strings.Contains(r.Detail, "w (world)") || !strings.Contains(r.Detail, "r (Region A)") {
		t.Fatalf("speed: %+v", r)
	}
	for _, c := range []struct {
		w, r []float64
		want Level
	}{{[]float64{300}, []float64{200}, OK}, {[]float64{300}, []float64{5}, Warn}, {nil, nil, Warn}, {[]float64{400}, nil, OK}} {
		if got, _ := judgeSpeed(c.w, c.r, RU); got != c.want {
			t.Errorf("%v %v: %s", c.w, c.r, got)
		}
	}
}

// Названия сетей без ответа попадают в вывод: по одному числу «4/5» не видно, у какого провайдера проблема.
func TestJudgeReachNamesSilentNetworks(t *testing.T) {
	var res []gpEntry
	mk := func(nw string, rcv int) gpEntry {
		e := gpEntry{Probe: gpProbe{Network: nw}}
		e.Result.Stats = &gpStats{Avg: 20, Rcv: rcv}
		return e
	}
	res = append(res, mk("Selectel", 3), mk("Timeweb", 0), mk("Beget", 3))
	lv, detail, _ := judgeReach(res, false, EN)
	if lv != Warn || !strings.Contains(detail, "2/3") || !strings.Contains(detail, "no answer: Timeweb") {
		t.Fatalf("%s %q", lv, detail)
	}
	_, all, _ := judgeReach([]gpEntry{mk("A", 3), mk("B", 3)}, false, EN)
	if strings.Contains(all, "no answer") {
		t.Fatalf("когда ответили все, сети не перечисляются: %q", all)
	}
}

func TestSpeedTargetsAreWithinCloudflareLimit(t *testing.T) {
	for _, s := range DefaultSpeedTargets() {
		if strings.Contains(s.URL, "speed.cloudflare.com") && s.Bytes > 8000000 {
			t.Errorf("Cloudflare отвечает 403 на размер больше 8 МБ: %d", s.Bytes)
		}
	}
}

func TestSpeedFailureShowsReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer srv.Close()
	r := testSpeed(context.Background(), EN, Net{HTTP: srv.Client(), SpeedTargets: []SpeedTarget{{Name: "x", URL: srv.URL, Region: "world", Bytes: 1 << 20}}})
	if r.Level != Warn || !strings.Contains(r.Detail, "not measured (HTTP 403)") {
		t.Fatalf("%+v", r)
	}
}

// Пороги проверки из других регионов: 80% и больше – норма (случайный отказ одного зонда из пяти не считается), меньше – предупреждение.
func TestJudgeReachThreshold(t *testing.T) {
	mk := func(rcv ...int) []gpEntry {
		var r []gpEntry
		for _, v := range rcv {
			e := gpEntry{Probe: gpProbe{Network: "N"}}
			e.Result.Stats = &gpStats{Avg: 20, Rcv: v}
			r = append(r, e)
		}
		return r
	}
	for _, c := range []struct {
		res  []gpEntry
		want Level
	}{{mk(3, 3, 3, 3, 3), OK}, {mk(3, 3, 3, 3, 0), OK}, {mk(3, 3, 3, 0, 0), Warn}, {mk(0, 0, 0, 0, 0), Warn}} {
		if got, _, _ := judgeReach(c.res, false, EN); got != c.want {
			t.Errorf("%d зондов: %s, ожидалось %s", len(c.res), got, c.want)
		}
	}
	if got, _, _ := judgeReach(mk(3, 3, 3, 3, 0), true, EN); got != OK {
		t.Error("4 из 5 по TCP тоже в норме")
	}
	if got, _, _ := judgeReach(mk(0, 0, 0, 0, 0), true, EN); got != Bad {
		t.Error("ни один зонд по TCP – не подходит")
	}
}
