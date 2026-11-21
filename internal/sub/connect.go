package sub

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"strings"

	"github.com/skip2/go-qrcode"

	"kitsune/internal/db"
)

// ConnectPlatform определяет устройство по User-Agent: ios, android, windows, mac или пусто.
func ConnectPlatform(userAgent string) string {
	ua := strings.ToLower(userAgent)
	switch {
	case strings.Contains(ua, "iphone"), strings.Contains(ua, "ipad"), strings.Contains(ua, "ipod"):
		return "ios"
	case strings.Contains(ua, "android"):
		return "android"
	case strings.Contains(ua, "windows"):
		return "windows"
	case strings.Contains(ua, "macintosh"), strings.Contains(ua, "mac os"):
		return "mac"
	}
	return ""
}

type connectApp struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`            // где скачать
	Note string `json:"note,omitempty"` // подсказка, если магазин не открылся
	URL2 string `json:"url2,omitempty"` // запасная ссылка
	Lab2 string `json:"lab2,omitempty"`
}

type connectPlatform struct {
	Label string       `json:"label"`
	Word  string       `json:"word"`
	Step3 string       `json:"step3"`
	Apps  []connectApp `json:"apps"`
}

// connectPlatforms – приложения по устройствам. Ссылки на магазины и релизы сторонние: они могут меняться,
// поэтому для каждого приложения, где это возможно, есть запасная ссылка.
var connectPlatforms = map[string]connectPlatform{
	"ios": {Label: "iPhone / iPad", Word: "iPhone или iPad",
		Step3: "В приложении нажмите большую кнопку включения. iPhone один раз спросит разрешение добавить VPN: нажмите «Разрешить» и введите код-пароль телефона.",
		Apps: []connectApp{
			{ID: "happ", Name: "Happ", URL: "https://apps.apple.com/ru/app/happ-lite/id6799917773", Note: "Если магазин не открылся или приложения нет, попробуйте международный вариант", URL2: "https://apps.apple.com/us/app/happ-proxy-utility/id6504287215", Lab2: "Happ в международном App Store"},
			{ID: "karing", Name: "Karing", URL: "https://apps.apple.com/us/app/karing/id6472431552"},
			{ID: "hiddify", Name: "Hiddify", URL: "https://apps.apple.com/us/app/hiddify-proxy-vpn/id6596777532"},
		}},
	"android": {Label: "Android", Word: "Android",
		Step3: "В приложении нажмите большую кнопку включения. Телефон один раз спросит разрешение на VPN: нажмите «ОК».",
		Apps: []connectApp{
			{ID: "happ", Name: "Happ", URL: "https://play.google.com/store/apps/details?id=com.happproxy", Note: "Если Google Play недоступен, скачайте файл напрямую", URL2: "https://github.com/Happ-proxy/happ-android/releases/latest/download/Happ.apk", Lab2: "Скачать Happ файлом (APK)"},
			{ID: "hiddify", Name: "Hiddify", URL: "https://play.google.com/store/apps/details?id=app.hiddify.com"},
			{ID: "v2rayng", Name: "v2rayNG", URL: "https://github.com/2dust/v2rayNG/releases/latest"},
		}},
	"windows": {Label: "Windows", Word: "компьютер с Windows",
		Step3: "В приложении нажмите кнопку включения. Если Windows спросит разрешение, нажмите «Да».",
		Apps: []connectApp{
			{ID: "happ", Name: "Happ", URL: "https://github.com/Happ-proxy/happ-desktop/releases/latest/download/setup-Happ.x64.exe"},
			{ID: "hiddify", Name: "Hiddify", URL: "https://github.com/hiddify/hiddify-app/releases/latest/download/Hiddify-Windows-Setup-x64.exe"},
		}},
	"mac": {Label: "Mac", Word: "Mac",
		Step3: "В приложении нажмите кнопку включения. Если Mac спросит разрешение, согласитесь и введите пароль.",
		Apps: []connectApp{
			{ID: "happ", Name: "Happ", URL: "https://apps.apple.com/ru/app/happ-proxy-utility/id6783623643", Note: "Если магазин не открылся или приложения нет, попробуйте международный вариант", URL2: "https://apps.apple.com/us/app/happ-proxy-utility/id6504287215", Lab2: "Happ в международном App Store"},
			{ID: "hiddify", Name: "Hiddify", URL: "https://apps.apple.com/us/app/hiddify-proxy-vpn/id6596777532"},
		}},
}

type connectData struct {
	Sub       string                     `json:"sub"`
	Detected  string                     `json:"detected"`
	Platforms map[string]connectPlatform `json:"platforms"`
	Order     []string                   `json:"order"`
}

type connectView struct {
	Name, State, StateClass string
	Active                  bool
	Data                    template.JS
	QR                      template.URL
	SubURL                  string
}

// ConnectPage рисует страницу «Подключить за пару минут»: пошаговая инструкция для человека, который не разбирается в VPN.
// platform – устройство, определённое по User-Agent (может быть пустым: тогда человек выбирает сам).
func ConnectPage(u db.User, subURL, platform string) []byte {
	v := connectView{Name: u.Name, SubURL: subURL, Active: u.Enable && u.Active()}
	if v.Active {
		v.State, v.StateClass = "Подписка активна", "on"
	} else {
		v.State, v.StateClass = "Подписка не активна: срок или лимит исчерпаны", "off"
	}
	// json.Marshal экранирует <, > и &, поэтому данные безопасно лежат внутри <script>
	raw, _ := json.Marshal(connectData{Sub: subURL, Detected: platform, Platforms: connectPlatforms, Order: []string{"ios", "android", "windows", "mac"}})
	v.Data = template.JS(raw)
	if png, err := qrcode.Encode(subURL, qrcode.Medium, 280); err == nil {
		v.QR = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
	}
	var b bytes.Buffer
	if err := connectTmpl.Execute(&b, v); err != nil {
		return []byte("Ошибка страницы подключения")
	}
	return b.Bytes()
}

var connectTmpl = template.Must(template.New("connect").Parse(`<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Подключить VPN</title>
<style>
:root{--bg:#0f0f12;--card:#1a1a20;--text:#f2f2f5;--muted:#9a9aa6;--accent:#ee6a44;--ok:#4ade80;--bad:#f87171;--line:rgba(128,128,140,.28);color-scheme:dark}
@media (prefers-color-scheme:light){:root{--bg:#f4f4f6;--card:#fff;--text:#17171c;--muted:#6b6b78;--accent:#d9552f;color-scheme:light}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:20px 16px 48px}
main{max-width:540px;margin:0 auto;display:flex;flex-direction:column;gap:14px}
h1{font-size:24px;margin:6px 0 0;line-height:1.2}.lead{color:var(--muted);margin:2px 0 0}
.card{background:var(--card);border-radius:20px;padding:18px}
.step{display:flex;gap:14px}.num{flex:none;width:34px;height:34px;border-radius:50%;background:var(--accent);color:#fff;display:grid;place-items:center;font-weight:800}
.step h2{font-size:17px;margin:4px 0 8px}.step p{margin:0 0 10px;color:var(--muted)}
.tabs{display:flex;flex-wrap:wrap;gap:8px}.tab{padding:9px 16px;border-radius:99px;border:1.5px solid var(--line);background:transparent;color:var(--text);font:inherit;font-size:15px;font-weight:600;cursor:pointer}
.tab.on{background:var(--text);color:var(--bg);border-color:var(--text)}
.app{display:flex;flex-direction:column;gap:2px;padding:12px 14px;border-radius:14px;border:1.5px solid var(--line);margin-top:10px}
.app b{font-size:16px}.app small{color:var(--muted)}
a.btn,button.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:12px 18px;border-radius:99px;border:1.5px solid var(--accent);background:transparent;color:var(--text);font:inherit;font-size:15px;font-weight:700;text-decoration:none;cursor:pointer}
a.btn:active,button.btn:active{background:rgba(238,106,68,.25)}
.btn.main{background:var(--accent);color:#fff;border-color:var(--accent)}
.row{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}
a.alt{color:var(--muted);font-size:14px}
.chip{display:inline-block;padding:3px 12px;border-radius:99px;font-weight:600;font-size:14px}.on{background:rgba(74,222,128,.15);color:var(--ok)}.off{background:rgba(248,113,113,.15);color:var(--bad)}
.copy{display:flex;gap:8px;margin-top:8px}.copy input{flex:1;min-width:0;padding:11px;border-radius:12px;border:1.5px solid var(--line);background:transparent;color:var(--text);font:13px ui-monospace,Menlo,monospace}
.qr{text-align:center;margin-top:10px}.qr img{width:190px;height:190px;border-radius:12px;background:#fff;padding:8px}
details{border-top:1px solid var(--line);padding:10px 0}details:first-of-type{border-top:0}summary{cursor:pointer;font-weight:700}details p{color:var(--muted);margin:8px 0 0}
.warn{background:rgba(248,113,113,.12);color:var(--text);border-radius:14px;padding:12px 14px}
.done{font-size:14px;color:var(--muted);text-align:center;margin-top:4px}
</style></head><body><main id="app">
<div><h1>Подключите VPN за пару минут</h1><p class="lead">{{.Name}}, нажимайте кнопки по порядку: всё займёт две-три минуты.</p></div>
<div><span class="chip {{.StateClass}}">{{.State}}</span></div>
{{if not .Active}}<div class="warn">Эта подписка сейчас не работает. Напишите тому, кто прислал вам ссылку: он продлит или включит её.</div>{{end}}

<div class="card step"><div class="num">1</div><div style="flex:1;min-width:0">
<h2>Скачайте приложение</h2><p>Выберите, на чём вы будете пользоваться VPN.</p>
<div class="tabs" id="tabs"></div><div id="apps"></div></div></div>

<div class="card step"><div class="num">2</div><div style="flex:1;min-width:0">
<h2>Добавьте VPN в приложение</h2><p>Когда приложение установлено, нажмите кнопку: оно откроется и добавит VPN само.</p>
<div id="adds" class="row"></div>
<details style="margin-top:12px"><summary>Не открылось? Добавьте вручную</summary>
<p>Скопируйте ссылку и вставьте её в приложении (кнопка «+», «Добавить из буфера» или «Подписка»).</p>
<div class="copy"><input id="suburl" readonly value="{{.SubURL}}"><button class="btn" id="copy" type="button">Копировать</button></div>
{{if .QR}}<div class="qr"><img alt="QR-код" src="{{.QR}}"><div class="done">Или наведите на этот QR-код камеру другого телефона</div></div>{{end}}
<p class="warn" style="margin-top:12px">Эта ссылка и QR-код работают как пароль: не публикуйте их и не отправляйте посторонним. Если ссылка попала не в те руки, попросите того, кто её дал, выпустить новую.</p>
</details></div></div>

<div class="card step"><div class="num">3</div><div style="flex:1;min-width:0">
<h2>Включите VPN</h2><p id="step3"></p><p style="margin:0">Готово: теперь сайты и приложения открываются через защищённое соединение.</p></div></div>

<div class="card"><h2 style="margin:0 0 6px;font-size:17px">Не получилось?</h2>
<details><summary>Приложение открылось, но VPN не включается</summary><p>Нажмите кнопку включения ещё раз и согласитесь на запрос разрешения. Если не помогло, выключите и снова включите VPN, потом перезапустите приложение.</p></details>
<details><summary>VPN включён, но сайты не открываются</summary><p>В приложении найдите «Обновить подписку» и нажмите. Потом выключите и включите VPN. Если есть список серверов, выберите другой.</p></details>
<details><summary>После сна телефона интернет появляется не сразу</summary><p>Это нормально: телефон экономит батарею. Выключите и снова включите VPN, и разрешите приложению работать в фоне без ограничений батареи.</p></details>
<details><summary>Приложение не находится в магазине</summary><p>В шаге 1 у некоторых приложений есть запасная ссылка: международный магазин или файл напрямую.</p></details>
<details><summary>Ничего не помогло</summary><p>Напишите тому, кто прислал вам ссылку: укажите, какой у вас телефон или компьютер и на каком шаге остановились.</p></details></div>
</main>
<script>
var D={{.Data}};
var cur=D.detected&&D.platforms[D.detected]?D.detected:"";
var path=location.pathname.replace(/\/$/,"");
function beacon(ev){try{navigator.sendBeacon(path+"/e/"+ev,"")}catch(e){}}
function $(i){return document.getElementById(i)}
function mk(tag,cls,txt){var e=document.createElement(tag);if(cls)e.className=cls;if(txt!=null)e.textContent=txt;return e}
var ADD={
 happ:function(u){return "happ://add/"+u},
 hiddify:function(u){return "hiddify://import/"+u+"#Kitsune"},
 karing:function(u){return "karing://install-config?url="+encodeURIComponent(u)+"&name=Kitsune"},
 v2rayng:function(u){return "v2rayng://install-sub/?url="+encodeURIComponent(u)+"&name=Kitsune"}
};
function render(){
 var tabs=$("tabs");tabs.textContent="";
 D.order.forEach(function(k){var b=mk("button","tab"+(k===cur?" on":""),D.platforms[k].label);b.type="button";b.onclick=function(){cur=k;render()};tabs.appendChild(b)});
 var apps=$("apps"),adds=$("adds");apps.textContent="";adds.textContent="";
 if(!cur){apps.appendChild(mk("p","","Выберите устройство выше: покажем подходящие приложения."));$("step3").textContent="Выберите устройство в шаге 1.";return}
 var p=D.platforms[cur];
 p.apps.forEach(function(a,i){
  var box=mk("div","app");var h=mk("b","",a.Name||a.name);box.appendChild(h);
  if(i===0)box.appendChild(mk("small","","Рекомендуем: проще всего"));
  var row=mk("div","row");var dl=mk("a","btn"+(i===0?" main":""),"Скачать");dl.href=a.url;dl.target="_blank";dl.rel="noopener noreferrer";dl.onclick=function(){beacon("store")};row.appendChild(dl);box.appendChild(row);
  if(a.note){box.appendChild(mk("small","",a.note))}
  if(a.url2){var x=mk("a","alt",a.lab2||"Запасная ссылка");x.href=a.url2;x.target="_blank";x.rel="noopener noreferrer";x.onclick=function(){beacon("store")};box.appendChild(x)}
  apps.appendChild(box);
  if(ADD[a.id]){var ab=mk("a","btn"+(i===0?" main":""),"Добавить в "+a.name);ab.href=ADD[a.id](D.sub);ab.onclick=function(){beacon("add")};adds.appendChild(ab)}
 });
 $("step3").textContent=p.step3;
}
$("copy").onclick=function(){var i=$("suburl");i.select();try{i.setSelectionRange(0,i.value.length);document.execCommand("copy");this.textContent="Скопировано";beacon("add")}catch(e){this.textContent="Выделите и скопируйте"}};
render();
</script></body></html>`))
