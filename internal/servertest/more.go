package servertest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"kitsune/internal/masking"
)

// Тесты с внешними сервисами, кроме региона, списков и проверки из других регионов: доступность сервисов с сервера (региональные ограничения), скорость, подбор сайта.

// GeoTarget – сервис, до которого сервер должен достучаться.
type GeoTarget struct{ Name, URL string }

// SpeedTarget – файл для замера скорости: читается не больше Bytes байт. Region – «RU» или «world».
type SpeedTarget struct {
	Name, URL, Region string
	Bytes             int
}

// DefaultGeoTargets – сервисы, региональные ограничения которых чаще всего важны.
func DefaultGeoTargets() []GeoTarget {
	return []GeoTarget{
		{"OpenAI API", "https://api.openai.com/v1/models"},
		{"Anthropic API", "https://api.anthropic.com/"},
		{"YouTube", "https://www.youtube.com/"},
		{"Netflix", "https://www.netflix.com/"},
		{"Spotify", "https://open.spotify.com/"},
		{"Telegram API", "https://api.telegram.org/"},
		{"GitHub", "https://github.com/"},
	}
}

// DefaultSpeedTargets – файлы с публичных зеркал и CDN: по регионам.
func DefaultSpeedTargets() []SpeedTarget {
	return []SpeedTarget{
		// Cloudflare отдаёт без отказа файлы до 8 МБ (на больший размер отвечает 403): берём ровно столько.
		{"Cloudflare", "https://speed.cloudflare.com/__down?bytes=8000000", "world", 8000000},
		{"CacheFly", "https://cachefly.cachefly.net/10mb.test", "world", 10 << 20},
		{"OVH", "https://proof.ovh.net/files/10Mb.dat", "world", 10 << 20},
		{"Yandex mirror", "https://mirror.yandex.ru/ubuntu/ls-lR.gz", "RU", 16 << 20},
		{"Selectel mirror", "https://mirror.selectel.ru/ubuntu/ls-lR.gz", "RU", 16 << 20},
	}
}

// MoreExternal – внешние тесты региональных ограничений и скорости (подбор сайта – отдельно, SNI).
func MoreExternal(n Net) []Test {
	return []Test{
		{ID: "regional", Group: "reach", External: true, Timeout: 40 * time.Second, Run: func(ctx context.Context, l Lang) Result { return testRegional(ctx, l, n) }},
		{ID: "speed", Group: "speed", External: true, Heavy: true, Timeout: 90 * time.Second, Run: func(ctx context.Context, l Lang) Result { return testSpeed(ctx, l, n) }},
	}
}

// ---- региональные ограничения ----

// geoVerdict: 403 и 451 – сервис отказал по региону или адресу; ниже 500 – ответил (для API 401 – норма: нет ключа).
func geoVerdict(status int) (ok bool, word string) {
	switch {
	case status == http.StatusForbidden || status == http.StatusUnavailableForLegalReasons:
		return false, "blocked"
	case status > 0 && status < 500:
		return true, "ok"
	}
	return false, "error"
}

type geoRes struct {
	name   string
	status int
	err    error
}

func testRegional(ctx context.Context, l Lang, n Net) Result {
	targets := n.GeoTargets
	if targets == nil {
		targets = DefaultGeoTargets()
	}
	res := make([]geoRes, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t GeoTarget) {
			defer wg.Done()
			rctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(rctx, http.MethodGet, t.URL, nil)
			if err != nil {
				res[i] = geoRes{name: t.Name, err: err}
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; "+userAgent+")")
			resp, err := n.HTTP.Do(req)
			if err != nil {
				res[i] = geoRes{name: t.Name, err: err}
				return
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			res[i] = geoRes{name: t.Name, status: resp.StatusCode}
		}(i, t)
	}
	wg.Wait()
	var parts []string
	blocked, failed := 0, 0
	for _, r := range res {
		ok, _ := geoVerdict(r.status)
		mark := L(l, "доступен", "reachable")
		switch {
		case r.err != nil:
			mark, failed = L(l, "не отвечает", "no answer"), failed+1
		case !ok:
			mark, blocked = L(l, "отказ (регион или адрес)", "refused (region or address)"), blocked+1
		}
		parts = append(parts, r.name+": "+mark)
	}
	title := L(l, "Доступ к сервисам с сервера", "Access to services from the server")
	lv, hint := OK, ""
	if blocked+failed > 0 {
		lv = Warn
		hint = L(l, "Часть сервисов недоступна с этого сервера. Если через прокси нужны именно они, возьмите адрес в другой стране.",
			"Some services are not available from this server. If you need exactly them through the proxy, take an address in another country.")
	}
	return Result{ID: "regional", Group: "reach", Level: lv, Title: title, Detail: strings.Join(parts, "; "), Hint: hint}
}

// ---- скорость ----

// speedMbit измеряет скорость чтения до t.Bytes байт с запросом диапазона (если сервер его не знает, читаем начало и обрываем).
func speedMbit(ctx context.Context, c *http.Client, t SpeedTarget) (float64, error) {
	rctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, t.URL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", t.Bytes-1))
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var first time.Time
	var got int64
	buf := make([]byte, 64<<10)
	for got < int64(t.Bytes) {
		k, err := resp.Body.Read(buf)
		if k > 0 {
			if first.IsZero() {
				first = time.Now() // время до первого байта в скорость не входит
			} else {
				got += int64(k)
			}
		}
		if err != nil {
			break
		}
	}
	el := time.Since(first).Seconds()
	if first.IsZero() || got < 256<<10 || el <= 0 {
		return 0, fmt.Errorf("too little data (%d bytes)", got)
	}
	return float64(got) * 8 / el / 1e6, nil
}

const speedWarnMbit = 20

// judgeSpeed: медленнее порога на любом направлении – предупреждение; не измерилось ничего – предупреждение.
func judgeSpeed(world, ru []float64, l Lang) (Level, string) {
	if len(world)+len(ru) == 0 {
		return Warn, L(l, "Скорость не удалось измерить: источники недоступны.", "Could not measure the speed: the sources are unavailable.")
	}
	slow := func(v []float64) bool {
		for _, x := range v {
			if x < speedWarnMbit {
				return true
			}
		}
		return false
	}
	if slow(world) || slow(ru) {
		return Warn, L(l, "Скорость ниже 20 Мбит/с хотя бы в одном направлении: для прокси это узко. Проверьте тариф и попробуйте тест ещё раз.",
			"Speed is below 20 Mbit/s in at least one direction: this is narrow for a proxy. Check the plan and run the test again.")
	}
	return OK, ""
}

func testSpeed(ctx context.Context, l Lang, n Net) Result {
	targets := n.SpeedTargets
	if targets == nil {
		targets = DefaultSpeedTargets()
	}
	var world, ru []float64
	var parts []string
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		v, err := speedMbit(ctx, n.HTTP, t)
		region := L(l, map[string]string{"RU": "Регион A", "world": "мир"}[t.Region], map[string]string{"RU": "Region A", "world": "world"}[t.Region])
		if err != nil {
			parts = append(parts, fmt.Sprintf("%s (%s): %s (%s)", t.Name, region, L(l, "не измерилось", "not measured"), err))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s (%s): %.0f %s", t.Name, region, v, L(l, "Мбит/с", "Mbit/s")))
		if t.Region == "RU" {
			ru = append(ru, v)
		} else {
			world = append(world, v)
		}
	}
	lv, hint := judgeSpeed(world, ru, l)
	detail := strings.Join(parts, "; ")
	best := 0.0
	for _, v := range append(append([]float64{}, world...), ru...) {
		if v > best {
			best = v
		}
	}
	if best > 0 {
		detail = fmt.Sprintf("%s %.0f %s. %s", L(l, "Канал не хуже", "The link is at least"), best, L(l, "Мбит/с", "Mbit/s"), detail)
	}
	return Result{ID: "speed", Group: "speed", Level: lv, Title: L(l, "Скорость скачивания", "Download speed"), Detail: detail, Hint: hint}
}

// ---- подбор сайта маскировки ----

// SNITest ищет среди соседних адресов /24 сайты, подходящие для REALITY. Перебор соседних адресов может вызвать жалобу у хостера, поэтому
// в общий прогон не входит и запускается отдельно.
func SNITest(n Net) Test {
	s := &state{n: n}
	return Test{ID: "sni", Group: "masking", External: true, Heavy: true, Timeout: 60 * time.Second, Run: func(ctx context.Context, l Lang) Result {
		title := L(l, "Сайт для маскировки REALITY", "REALITY masking site")
		info, err := s.get(ctx)
		if err != nil {
			return Result{ID: "sni", Group: "masking", Level: Skip, Title: title, Detail: err.Error(), Hint: L(l, "Не удалось узнать адрес сервера.", "Could not determine the server address.")}
		}
		c := masking.Scan(ctx, info.IP, 6)
		if len(c) == 0 {
			return Result{ID: "sni", Group: "masking", Level: Warn, Title: title, Detail: L(l, "подходящих соседей не найдено", "no suitable neighbours found"),
				Hint: L(l, "Подойдёт сайт крупной компании с TLS 1.3 и HTTP/2: проверьте вручную командой kit sni check ДОМЕН.", "A large company's site with TLS 1.3 and HTTP/2 works: check by hand with kit sni check DOMAIN.")}
		}
		var parts []string
		for _, x := range c {
			parts = append(parts, fmt.Sprintf("%s (%d %s)", x.Domain, x.LatencyMS, L(l, "мс", "ms")))
		}
		return Result{ID: "sni", Group: "masking", Level: OK, Title: title, Detail: strings.Join(parts, ", ")}
	}}
}
