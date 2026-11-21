package check

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/proto"
	"kitsune/internal/site"
)

// «Паспорт безопасности»: что на самом сервере видно снаружи.
// Проверки идут с самого сервера, поэтому они не показывают блокировку у провайдера: только то, что видит любой, кто постучится на порты.

const postureGroup = "Безопасность"

// postureScore считает оценку из 100: серьёзная проблема снимает 25 баллов, предупреждение – 10.
func postureScore(items []Item) int {
	score := 100
	for _, it := range items {
		switch it.Level {
		case Bad:
			score -= 25
		case Warn:
			score -= 10
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

func postureVerdict(score int) string {
	switch {
	case score >= 90:
		return "сервер выглядит как обычный"
	case score >= 70:
		return "есть что улучшить"
	case score >= 40:
		return "у сервера много открытых деталей"
	}
	return "у сервера мало защиты"
}

// postureItems выполняет проверки безопасности и добавляет первой строкой общую оценку.
func postureItems() []Item {
	items := collect(checkPostureInbounds, checkPostureSNI, checkPosturePanel, checkPostureStub, checkPosturePorts, checkPostureStability, checkPostureCores)
	if len(items) == 0 {
		return []Item{{Group: postureGroup, Level: Info, Text: "Нет включённых подключений: проверять нечем"}}
	}
	items = append(items, collect(checkPosture2FA)...)
	score := postureScore(items)
	lvl := OK // оценка сама не считается проблемой: причины видны в строках ниже
	if score < 70 {
		lvl = Info
	}
	recordPassport(score, items)
	head := Item{Group: postureGroup, Level: lvl, Text: fmt.Sprintf("Оценка безопасности: %d из 100 – %s. Проверка идёт с самого сервера и не показывает состояние сети у вашего провайдера.", score, postureVerdict(score))}
	return append([]Item{head}, items...)
}

func inboundPort(ib db.Inbound, env proto.Env) int {
	if proto.Routed(ib, env) {
		return 443
	}
	return ib.Port
}

// tlsLook делает рукопожатие TLS 1.3 с заданным SNI и возвращает состояние соединения.
func tlsLook(addr, sni string, alpn []string) (tls.ConnectionState, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	raw, err := d.Dial("tcp", addr)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(8 * time.Second))
	c := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, NextProtos: alpn}) //nolint:gosec // смотрим на ответ, а не доверяем ему
	if err := c.Handshake(); err != nil {
		return tls.ConnectionState{}, err
	}
	return c.ConnectionState(), nil
}

// checkPostureInbounds: на постороннее подключение сервер должен отвечать как настоящий сайт, а не сбрасывать связь.
func checkPostureInbounds(add adder) {
	if db.DB == nil {
		return
	}
	inbounds, err := db.GetInbounds()
	if err != nil {
		return
	}
	env := core.PublicEnv()
	var selfSigned []string
	for _, ib := range inbounds {
		if !ib.Enable {
			continue
		}
		s := proto.ParseSettings(ib.Settings)
		port := inboundPort(ib, env)
		switch proto.Kind(ib.Kind) {
		case proto.VlessReality, proto.VlessXHTTP:
			if s.SNI == "" {
				continue
			}
			if !tcpListens(port) {
				// остановленное ядро ловят другие проверки, но оценку безопасности это подключение не подтверждает
				add(postureGroup, Info, fmt.Sprintf("%s: порт %d не слушается, ответ на чужие запросы не проверен", ib.Tag, port), "")
				continue
			}
			st, err := tlsLook(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), s.SNI, nil)
			fix := ""
			if proto.Kind(ib.Kind) == proto.VlessReality {
				fix = "sni:" + strconv.Itoa(ib.ID) // другой сайт-прикрытие предлагаем только для обычного REALITY
			}
			switch {
			case err != nil:
				add(postureGroup, Bad, fmt.Sprintf("%s: на постороннее подключение сервер не отвечает как сайт (%s). Так он выглядит необычно", ib.Tag, trimErr(err.Error())), fix)
			case len(st.PeerCertificates) == 0 || st.PeerCertificates[0].VerifyHostname(s.SNI) != nil:
				add(postureGroup, Warn, fmt.Sprintf("%s: чужой запрос получает сертификат, не подходящий к %s. Сайт-прикрытие и SNI должны совпадать", ib.Tag, s.SNI), fix)
			default:
				add(postureGroup, OK, fmt.Sprintf("%s: чужой запрос получает ответ настоящего сайта %s", ib.Tag, s.SNI), "")
			}
			if port != 443 {
				add(postureGroup, Info, fmt.Sprintf("%s: REALITY на порту %d. На 443 он выглядит привычнее (режим «все на 443» в настройках)", ib.Tag, port), "")
			}
		case proto.VlessWS, proto.VmessWS, proto.TrojanGRPC, proto.Hysteria2, proto.TUIC, proto.Naive:
			if s.CertMode != "custom" && s.CertMode != "acme" {
				selfSigned = append(selfSigned, ib.Tag)
			}
		}
	}
	if len(selfSigned) > 0 { // одна причина – одна строка и один вычет, сколько бы подключений ни было
		fix, how := "", "Чтобы исправить: в «Настройки → Сеть и сертификаты» включите Let's Encrypt для домена панели (домен должен указывать на этот сервер), затем нажмите «Исправить»: подключения получат тот же сертификат"
		if t := core.LoadPanelTLS(); t.Mode == "acme" && strings.TrimSpace(t.Domain) != "" {
			fix, how = "certs", "У панели уже есть домен с Let's Encrypt: подключения можно перевести на тот же сертификат кнопкой «Исправить»"
		}
		add(postureGroup, Warn, "Самоподписанный сертификат у подключений: "+strings.Join(selfSigned, ", ")+". Он отличается от обычного сайта. "+how, fix)
	}
}

// checkPostureSNI: сайт-прикрытие для REALITY должен поддерживать TLS 1.3 и h2, иначе рукопожатие выглядит странно.
func checkPostureSNI(add adder) {
	if db.DB == nil {
		return
	}
	inbounds, err := db.GetInbounds()
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, ib := range inbounds {
		if !ib.Enable {
			continue
		}
		if k := proto.Kind(ib.Kind); k != proto.VlessReality && k != proto.VlessXHTTP {
			continue
		}
		fix := ""
		if proto.Kind(ib.Kind) == proto.VlessReality {
			fix = "sni:" + strconv.Itoa(ib.ID)
		}
		sni := proto.ParseSettings(ib.Settings).SNI
		if sni == "" || seen[sni] || net.ParseIP(sni) != nil {
			continue
		}
		seen[sni] = true
		st, err := tlsLook(net.JoinHostPort(sni, "443"), sni, []string{"h2", "http/1.1"})
		switch {
		case err != nil:
			add(postureGroup, Warn, fmt.Sprintf("Сайт-прикрытие %s не отвечает с этого сервера по TLS 1.3 (%s): REALITY на нём работать не будет", sni, trimErr(err.Error())), fix)
		case st.NegotiatedProtocol != "h2":
			add(postureGroup, Warn, fmt.Sprintf("Сайт-прикрытие %s не поддерживает HTTP/2: обычный браузер ходит иначе, выберите другой сайт", sni), fix)
		default:
			add(postureGroup, OK, fmt.Sprintf("Сайт-прикрытие %s: TLS 1.3 и HTTP/2", sni), "")
		}
	}
}

func panelPort() string {
	addr := os.Getenv("KITSUNE_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "8080"
	}
	return p
}

// checkPosturePanel: панель не должна отвечать посторонним – ни на корне, ни на известных адресах.
func checkPosturePanel(add adder) {
	if db.DB == nil {
		return
	}
	path := strings.Trim(db.GetSetting("panel_path", ""), "/")
	if path == "" {
		add(postureGroup, Warn, "Панель отвечает на любой адрес: задайте секретный путь входа, тогда посторонним она не видна", "panelpath")
		return
	}
	cl := &http.Client{Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := "http://127.0.0.1:" + panelPort()
	if t := core.LoadPanelTLS(); t.Mode != "" && t.Mode != "off" && t.Port > 0 {
		// на обычном HTTP при включённом HTTPS панель только перенаправляет (308): смотрим то, что видно на HTTPS-порту
		base = "https://127.0.0.1:" + strconv.Itoa(t.Port)
		cl.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // ищем, что отвечает порт, а не доверяем сертификату
	}
	for _, p := range []string{"/", "/api/v1/users", "/login"} {
		resp, err := cl.Get(base + p)
		if err != nil {
			return // панель слушает не здесь (туннель или другой порт): проверить нечем
		}
		code := resp.StatusCode
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		if code != http.StatusNotFound {
			add(postureGroup, Bad, fmt.Sprintf("Адрес %s отвечает кодом %d вместо 404: панель видна посторонним", p, code), "")
			return
		}
	}
	add(postureGroup, OK, "Панель скрыта за секретным путём: посторонним запросам отвечает 404, как обычный сервер", "")
}

var leakWords = []string{"kitsune", "xray", "vless", "gin-gonic", "go-http-client", "sing-box"}

// leakIn ищет в тексте слова, которые выдают VPN или панель.
func leakIn(s string) []string {
	s = strings.ToLower(s)
	var out []string
	for _, w := range leakWords {
		if strings.Contains(s, w) {
			out = append(out, w)
		}
	}
	return out
}

// checkPostureStub: страница-заглушка не должна называть наш продукт ни в заголовках, ни в тексте.
func checkPostureStub(add adder) {
	u := site.LocalURL()
	if u == "" {
		return
	}
	cl := &http.Client{Timeout: 4 * time.Second}
	resp, err := cl.Get(u)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<18))
	var hdr strings.Builder
	for k, v := range resp.Header {
		hdr.WriteString(k + ": " + strings.Join(v, ",") + "\n")
	}
	if hits := leakIn(hdr.String() + string(body)); len(hits) > 0 {
		add(postureGroup, Bad, "Страница-заглушка содержит слова, которые указывают на VPN: "+strings.Join(hits, ", "), "")
		return
	}
	add(postureGroup, OK, "Страница-заглушка не содержит слов, указывающих на VPN или панель", "")
}

var riskyPorts = map[int]string{
	23: "Telnet", 445: "SMB", 139: "NetBIOS", 1433: "MS SQL", 2375: "Docker без защиты", 3306: "MySQL", 3389: "RDP",
	5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

// openPorts читает слушающие TCP-порты, доступные снаружи (Linux).
func openPorts() []int {
	set := map[int]bool{}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Scan() // заголовок
		for sc.Scan() {
			if port, ok := parseListen(sc.Text()); ok {
				set[port] = true
			}
		}
		fh.Close()
	}
	var out []int
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// parseListen разбирает строку /proc/net/tcp: нужны сокеты в состоянии LISTEN не на loopback.
func parseListen(line string) (int, bool) {
	f := strings.Fields(line)
	if len(f) < 4 || f[3] != "0A" {
		return 0, false
	}
	i := strings.LastIndex(f[1], ":")
	if i < 0 {
		return 0, false
	}
	ip, port := f[1][:i], f[1][i+1:]
	// вся сеть 127.0.0.0/8 (в /proc адрес записан задом наперёд: первый октет в конце) и ::1; сюда входит и локальный DNS 127.0.0.53
	if (len(ip) == 8 && strings.HasSuffix(ip, "7F")) || ip == "00000000000000000000000001000000" {
		return 0, false
	}
	p, err := strconv.ParseInt(port, 16, 32)
	if err != nil {
		return 0, false
	}
	return int(p), true
}

// checkPosturePorts: лишние открытые порты раскрывают о сервере больше, чем нужно.
func checkPosturePorts(add adder) {
	if db.DB == nil {
		return
	}
	known := map[int]bool{22: true, 80: true, 443: true}
	if pp, err := strconv.Atoi(panelPort()); err == nil {
		known[pp] = true
	}
	if t := core.LoadPanelTLS(); t.Mode != "" && t.Mode != "off" && t.Port > 0 {
		known[t.Port] = true // HTTPS-порт самой панели
	}
	env := core.PublicEnv()
	if inbounds, err := db.GetInbounds(); err == nil {
		for _, ib := range inbounds {
			known[inboundPort(ib, env)] = true
		}
	}
	ports := openPorts()
	if len(ports) == 0 {
		return
	}
	var risky, other []string
	for _, p := range ports {
		if known[p] {
			continue
		}
		if name, ok := riskyPorts[p]; ok {
			risky = append(risky, fmt.Sprintf("%d (%s)", p, name))
		} else if p < 49152 { // выше – временные порты исходящих соединений
			other = append(other, strconv.Itoa(p))
		}
	}
	if len(risky) > 0 {
		add(postureGroup, Bad, "Снаружи открыты опасные порты: "+strings.Join(risky, ", ")+". Закройте их в файрволе", "")
	}
	if len(other) > 0 {
		if len(other) > 8 {
			other = append(other[:8], "…")
		}
		add(postureGroup, Info, "Открыты порты, не связанные с Kitsune: "+strings.Join(other, ", ")+". Лишнее лучше закрыть", "")
	}
	if len(risky) == 0 && len(other) == 0 {
		add(postureGroup, OK, "Снаружи открыты только нужные порты", "")
	}
}

// recordPassport сохраняет результат в историю: только строки, которые не «в порядке».
func recordPassport(score int, items []Item) {
	if db.DB == nil {
		return
	}
	var lines []db.PassportLine
	bad, warn := 0, 0
	for _, it := range items {
		switch it.Level {
		case Bad:
			bad++
		case Warn:
			warn++
		default:
			continue
		}
		lines = append(lines, db.PassportLine{Level: it.Level, Text: it.Text})
	}
	_ = db.AddPassport(score, bad, warn, lines)
}

// RecordPassport выполняет проверки безопасности и записывает результат в историю (для фонового запуска).
func RecordPassport() { _ = postureItems() }

// checkPostureStability: что показали проверки стабильности соединения, присланные людьми из их сетей.
func checkPostureStability(add adder) {
	if db.DB == nil {
		return
	}
	total, stalled, last := db.StabilitySummary(14)
	switch {
	case total == 0:
		add(postureGroup, Info, "Проверка стабильности соединения из сети человека не проводилась: в «Здоровье» создайте ссылку и откройте её с телефона в мобильной сети", "")
	case stalled > 0:
		fix := ""
		if db.GetSetting("sub_udp_first", "0") != "1" && hasUDPInboundDB() {
			fix = "udpfirst"
		}
		add(postureGroup, Warn, fmt.Sprintf("Остановка передачи: в %d из %d проверок передача останавливалась (последняя %s). TCP-подключения (REALITY, XHTTP) у таких людей могут не пройти: поставьте UDP-подключения первыми, используйте мост или смените хостинг",
			stalled, total, time.UnixMilli(last.At).Format("02.01 15:04")), fix)
	default:
		add(postureGroup, OK, fmt.Sprintf("Проверка стабильности соединения: соединение не обрывается (проверок: %d, последняя %s)", total, time.UnixMilli(last.At).Format("02.01 15:04")), "")
	}
}

func hasUDPInboundDB() bool {
	inbounds, _ := db.GetInbounds()
	for _, ib := range inbounds {
		if info, ok := proto.Get(proto.Kind(ib.Kind)); ok && ib.Enable && info.Net == "udp" {
			return true
		}
	}
	return false
}

// checkPostureCores: ядра должны быть последних версий, иначе оценка падает на 10. В новых выпусках Xray и других ядер исправляют
// ошибки протоколов и маскировки. Оценка снижается и при проверенной нами версии, и при свежем выпуске: цель – не отставать.
// Строка единая, со списком ядер: оценка не падает по 10 баллов за каждое.
// latestCores – источник сведений о версиях ядер; в тестах подменяется.
var latestCores = core.LatestVersions

func checkPostureCores(add adder) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var old []string
	xrayBreaksSingbox := false
	for _, l := range latestCores(ctx) {
		if !l.Newer || l.Latest == "" {
			continue
		}
		desc := fmt.Sprintf("%s (стоит %s, вышла %s)", coreTitle(l.ID), l.Pinned, l.Latest)
		if l.Fresh {
			desc = fmt.Sprintf("%s (стоит %s, вышла %s, выпуск младше 3 суток)", coreTitle(l.ID), l.Pinned, l.Latest)
		}
		old = append(old, desc)
		if l.ID == "xray" && verAtLeast(l.Latest, "26.9.8") {
			xrayBreaksSingbox = true
		}
	}
	if len(old) > 0 {
		add(postureGroup, Warn, "Не установлены последние версии ядер: "+strings.Join(old, "; ")+". Оценка здоровья снижена на 10. Обновите в «Настройках» → «Ядра»", "")
		if xrayBreaksSingbox {
			add(postureGroup, Info, "Осторожно с Xray 26.9.8 и новее: его REALITY не принимает клиентов без ключа X25519MLKEM768 (Karing, Hiddify и другие на sing-box). Перед обновлением проверьте своё приложение", "")
		}
	}
}

func coreTitle(id string) string {
	switch id {
	case "xray":
		return "Xray"
	case "singbox":
		return "sing-box"
	}
	return id
}

// verAtLeast: версия a (вида 26.9.8, возможна приставка v) не ниже b; сравнение по числам.
func verAtLeast(a, b string) bool {
	pa, pb := strings.Split(strings.TrimPrefix(a, "v"), "."), strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(strings.TrimFunc(pa[i], func(r rune) bool { return r < '0' || r > '9' }))
		}
		y, _ = strconv.Atoi(pb[i])
		if x != y {
			return x > y
		}
	}
	return true
}

// checkPosture2FA: без двухфакторного входа оценка не доходит до 100. Включить его может только человек с приложением-аутентификатором,
// поэтому автоисправления нет: строка подсказывает, где это сделать.
func checkPosture2FA(add adder) {
	if db.DB == nil || db.GetSetting("totp_enabled", "") == "1" {
		return
	}
	add(postureGroup, Warn, "Не включён двухфакторный вход: оценка здоровья снижена на 10. Включите в «Настройках» → «Безопасность» (или командой kit 2fa on): даже если пароль утечёт, зайти без телефона не получится", "")
}
