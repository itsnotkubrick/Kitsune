package sub

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/url"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"

	"kitsune/internal/db"
)

// WantsPage: ссылку подписки открыли в браузере (а не приложением) – вместо списка ссылок покажем страницу.
func WantsPage(accept, userAgent, format, page string) bool {
	if page == "1" {
		return true
	}
	if format != "" {
		return false
	}
	return strings.Contains(accept, "text/html") && strings.Contains(userAgent, "Mozilla/")
}

type pageApp struct {
	Name string
	URL  template.URL
	Hint string
}

type pageData struct {
	Name, State, StateClass string
	Used, Limit             string
	Percent                 int
	HasLimit                bool
	Expiry                  string
	Devices                 string
	SubURL                  string
	QR                      template.URL
	Apps                    []pageApp
}

func humanBytes(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d Б", n)
	}
	f, i := float64(n), 0
	for f >= u && i < 4 {
		f /= u
		i++
	}
	return fmt.Sprintf("%.1f %s", f, []string{"Б", "КБ", "МБ", "ГБ", "ТБ"}[i])
}

// percentUsed – доля использованного трафика 0..100 без переполнения целых.
func percentUsed(used, limit int64) int {
	if used <= 0 || limit <= 0 {
		return 0
	}
	if used >= limit {
		return 100
	}
	return int(float64(used) / float64(limit) * 100)
}

// expiryText – срок подписки словами: остаток в днях, а в последние сутки – в часах.
func expiryText(expiryMs int64, now time.Time) string {
	switch {
	case expiryMs <= 0: // отрицательное значение Active() тоже считает «без срока»
		return "бессрочно"
	}
	t := time.UnixMilli(expiryMs)
	left := t.Sub(now)
	switch {
	case left < 0:
		return "истёк " + t.Format("02.01.2006")
	case left >= 24*time.Hour:
		return fmt.Sprintf("до %s (ещё %d дн.)", t.Format("02.01.2006"), int(left.Hours()/24))
	case left >= time.Hour:
		return fmt.Sprintf("до %s (ещё %d ч.)", t.Format("02.01.2006 15:04"), int(left.Hours()))
	}
	return fmt.Sprintf("до %s (меньше часа)", t.Format("02.01.2006 15:04"))
}

func appLinks(subURL, name string) []pageApp {
	q := url.QueryEscape
	return []pageApp{
		{"Happ", template.URL("happ://add/" + subURL), "iPhone, Android, macOS, Windows"},
		{"Hiddify", template.URL("hiddify://import/" + subURL + "#" + q(name)), "все платформы"},
		{"Streisand", template.URL("streisand://import/" + subURL + "#" + q(name)), "iPhone, macOS"},
		{"Karing", template.URL("karing://install-config?url=" + q(subURL) + "&name=" + q(name)), "все платформы"},
		{"v2rayNG", template.URL("v2rayng://install-sub/?url=" + q(subURL) + "#" + q(name)), "Android"},
		{"Shadowrocket", template.URL("shadowrocket://add/sub://" + base64.StdEncoding.EncodeToString([]byte(subURL)) + "?remark=" + q(name)), "iPhone"},
		{"sing-box", template.URL("sing-box://import-remote-profile?url=" + q(subURL) + "#" + q(name)), "iPhone, Android"},
		{"Clash Verge", template.URL("clash://install-config?url=" + q(subURL) + "&name=" + q(name)), "Windows, macOS, Linux"},
	}
}

// Page рисует страницу подписки: статус, трафик, срок, QR и кнопки «открыть в приложении».
func Page(u db.User, subURL string) []byte {
	d := pageData{Name: u.Name, SubURL: subURL, Used: humanBytes(u.UsedTraffic), Apps: appLinks(subURL, "Kitsune")}
	switch {
	case !u.Enable:
		d.State, d.StateClass = "Отключена", "off"
	case !u.Active():
		d.State, d.StateClass = "Лимит или срок исчерпаны", "off"
	default:
		d.State, d.StateClass = "Активна", "on"
	}
	if u.TrafficLimit > 0 {
		d.HasLimit, d.Limit = true, humanBytes(u.TrafficLimit)
		d.Percent = percentUsed(u.UsedTraffic, u.TrafficLimit)
	}
	d.Expiry = expiryText(u.ExpiryTime, time.Now())
	if u.IPLimit > 0 {
		d.Devices = fmt.Sprintf("до %d", u.IPLimit)
	}
	if png, err := qrcode.Encode(subURL, qrcode.Medium, 280); err == nil {
		d.QR = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
	}
	var b bytes.Buffer
	if err := pageTmpl.Execute(&b, d); err != nil {
		return []byte("Ошибка страницы подписки")
	}
	return b.Bytes()
}

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Подписка</title>
<style>
:root{--bg:#0f0f12;--card:#1a1a20;--text:#f2f2f5;--muted:#9a9aa6;--fox:#ff7a3d;--ok:#4ade80;--bad:#f87171;color-scheme:dark}
@media (prefers-color-scheme:light){:root{--bg:#f4f4f6;--card:#fff;--text:#17171c;--muted:#6b6b78;color-scheme:light}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:20px 16px 40px}
main{max-width:520px;margin:0 auto;display:flex;flex-direction:column;gap:14px}
h1{font-size:22px;margin:4px 0 0}h2{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:0 0 10px}
.card{background:var(--card);border-radius:18px;padding:18px}
.row{display:flex;justify-content:space-between;gap:12px;padding:6px 0}.row span:first-child{color:var(--muted)}
.chip{display:inline-block;padding:2px 12px;border-radius:99px;font-weight:600;font-size:13px}.on{background:rgba(74,222,128,.15);color:var(--ok)}.off{background:rgba(248,113,113,.15);color:var(--bad)}
.bar{height:8px;border-radius:9px;background:rgba(128,128,140,.25);overflow:hidden;margin-top:6px}.bar b{display:block;height:100%;background:var(--fox)}
.apps{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
.apps a{display:flex;flex-direction:column;gap:2px;padding:12px;border-radius:14px;background:rgba(255,122,61,.12);color:var(--text);text-decoration:none;font-weight:700}
.apps a small{font-weight:400;color:var(--muted);font-size:12px}.apps a:active{background:rgba(255,122,61,.3)}
.qr{text-align:center}.qr img{width:200px;height:200px;border-radius:12px;background:#fff;padding:8px}
.copy{display:flex;gap:8px}.copy input{flex:1;min-width:0;padding:10px;border-radius:10px;border:1px solid rgba(128,128,140,.3);background:transparent;color:var(--text);font:13px ui-monospace,Menlo,monospace}
button{padding:10px 16px;border:0;border-radius:10px;background:var(--fox);color:#fff;font-weight:700;font-size:14px;cursor:pointer}
ol{margin:0;padding-left:20px;color:var(--muted)}ol b{color:var(--text)}
</style></head><body><main>
<h1>Подписка</h1>
<div class="card">
<div class="row"><span>Статус</span><span class="chip {{.StateClass}}">{{.State}}</span></div>
<div class="row"><span>Трафик</span><span>{{.Used}}{{if .HasLimit}} из {{.Limit}}{{else}}, без ограничений{{end}}</span></div>
{{if .HasLimit}}<div class="bar"><b style="width:{{.Percent}}%"></b></div>{{end}}
<div class="row"><span>Срок</span><span>{{.Expiry}}</span></div>
{{if .Devices}}<div class="row"><span>Устройств</span><span>{{.Devices}}</span></div>{{end}}
</div>
<div class="card"><h2>Открыть в приложении</h2>
<div class="apps">{{range .Apps}}<a href="{{.URL}}"><span>{{.Name}}</span><small>{{.Hint}}</small></a>{{end}}</div>
<p style="color:var(--muted);font-size:13px;margin:12px 0 0">Нет приложения? Установите любое из списка, затем нажмите на его кнопку здесь.</p></div>
<div class="card"><h2>Как подключиться</h2><ol>
<li>Установите приложение (например, <b>Happ</b> или <b>Hiddify</b>).</li>
<li>Нажмите кнопку нужного приложения выше или отсканируйте QR с другого устройства.</li>
<li>Разрешите добавить профиль и включите соединение.</li></ol></div>
<div class="card qr"><h2>QR-код подписки</h2>{{if .QR}}<img alt="QR" src="{{.QR}}">{{end}}</div>
<div class="card"><h2>Ссылка подписки</h2><div class="copy"><input id="u" readonly value="{{.SubURL}}"><button onclick="var i=document.getElementById('u');i.select();navigator.clipboard?navigator.clipboard.writeText(i.value):document.execCommand('copy');this.textContent='Скопировано'">Копировать</button></div></div>
</main></body></html>`))
