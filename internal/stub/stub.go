// Package stub содержит страницы-заглушки: ими сервер отвечает постороннему, который стучится не по протоколу
// (например, Hysteria2 по HTTP/3), чтобы сервер выглядел как обычный сайт.
package stub

import (
	"crypto/rand"
	"strings"
	"sync"
)

type Template struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	html  string
}

const base = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{TITLE}}</title>
<style>*{box-sizing:border-box}body{margin:0;font:16px/1.6 -apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#1f2937;background:{{BG}}}
.w{max-width:880px;margin:0 auto;padding:64px 24px}h1{font-size:40px;margin:0 0 12px}p{color:#4b5563;max-width:620px}
.c{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-top:40px}.k{background:#fff;border-radius:14px;padding:20px;box-shadow:0 1px 6px rgba(0,0,0,.08)}
.k b{display:block;margin-bottom:6px}footer{margin-top:56px;font-size:13px;color:#9ca3af}</style></head>
<body><div class="w"><h1>{{H1}}</h1><p>{{LEAD}}</p><div class="c">{{CARDS}}</div><footer>© {{FOOT}}</footer></div></body></html>`

func build(title, bg, h1, lead, foot string, cards ...[2]string) string {
	var c strings.Builder
	for _, k := range cards {
		c.WriteString(`<div class="k"><b>` + k[0] + `</b>` + k[1] + `</div>`)
	}
	r := strings.NewReplacer("{{TITLE}}", title, "{{BG}}", bg, "{{H1}}", h1, "{{LEAD}}", lead, "{{FOOT}}", foot, "{{CARDS}}", c.String())
	return r.Replace(base)
}

// DefaultID – заглушка по умолчанию: ею отвечают и сайт на своём домене, и Hysteria, когда настройку прочитать не удалось.
const DefaultID = "nginx"

// Templates – доступные заглушки.
var Templates = []Template{
	{"studio", "Студия: лендинг", build("Northwind Studio", "#f3f4f6", "Northwind Studio", "We design and build websites and mobile apps for growing companies.", "Northwind Studio",
		[2]string{"Design", "Brand identity, interfaces and design systems."}, [2]string{"Development", "Web, mobile and cloud engineering."}, [2]string{"Support", "Maintenance and growth after launch."})},
	{"blog", "Блог", build("Field Notes", "#fffaf0", "Field Notes", "Short essays about travel, photography and slow living.", "Field Notes",
		[2]string{"Morning light", "How to photograph a city before it wakes."}, [2]string{"Slow trains", "Notes from a week across the mountains."}, [2]string{"Film or digital", "A practical comparison."})},
	{"docs", "Документация", build("Developer Docs", "#f8fafc", "Documentation", "Guides, API reference and release notes for the platform.", "Developer Docs",
		[2]string{"Getting started", "Install the SDK and make your first request."}, [2]string{"API reference", "Endpoints, parameters and examples."}, [2]string{"Changelog", "What is new in the latest release."})},
	{"status", "Страница статуса", build("System status", "#ecfdf5", "All systems operational", "Updated a few minutes ago. No incidents reported in the last 90 days.", "Status",
		[2]string{"API", "Operational"}, [2]string{"Dashboard", "Operational"}, [2]string{"Database", "Operational"})},
	{"soon", "Скоро открытие", build("Coming soon", "#111827", "Coming soon", "We are working on something new. Leave your email and we will let you know.", "All rights reserved",
		[2]string{"Launch", "Q4"}, [2]string{"Contact", "hello@example.com"})},
	{"nginx", "Welcome to nginx", `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`},
}

// CustomID – идентификатор страницы, которую пользователь загрузил сам.
const CustomID = "custom"

// MaxCustom – предел размера своей страницы (байт): она встраивается в конфиг и отдаётся целиком.
const MaxCustom = 256 << 10

var (
	customMu sync.RWMutex
	custom   string
)

// SetCustom задаёт свою страницу (пустая строка – удаляет).
func SetCustom(html string) {
	customMu.Lock()
	custom = html
	customMu.Unlock()
}

// Custom возвращает свою страницу (пусто, если не задана).
func Custom() string {
	customMu.RLock()
	defer customMu.RUnlock()
	return custom
}

// List – готовые заглушки и, если есть, своя страница.
func List() []Template {
	out := append([]Template(nil), Templates...)
	if c := Custom(); c != "" {
		out = append(out, Template{ID: CustomID, Title: "Своя страница", html: c})
	}
	return out
}

// ListWith – список как List; если выбранной страницы в нём нет, она идёт первой.
func ListWith(cur string) []Template {
	out := List()
	if t, ok := extraTitle(cur); ok {
		out = append([]Template{{ID: cur, Title: t}}, out...)
	}
	return out
}

// HTML возвращает страницу по идентификатору (неизвестный идентификатор – страница по умолчанию).
func HTML(id string) string {
	if h, ok := extraHTML(id); ok {
		return h
	}
	if id == CustomID {
		if c := Custom(); c != "" {
			return c
		}
	}
	for _, t := range Templates {
		if t.ID == id {
			return t.html
		}
	}
	return Templates[0].html
}

func Exists(id string) bool {
	if extraHas(id) {
		return true
	}
	if id == CustomID {
		return Custom() != ""
	}
	for _, t := range Templates {
		if t.ID == id {
			return true
		}
	}
	return false
}

// Title – подпись заглушки для списка в панели.
func Title(id string) string {
	if t, ok := extraTitle(id); ok {
		return t
	}
	for _, t := range List() {
		if t.ID == id {
			return t.Title
		}
	}
	return id
}

// RandomID выбирает случайную заглушку, не равную except (пустая строка – любая); своя страница не выбирается.
func RandomID(except string) string {
	if id, ok := extraRandom(except); ok {
		return id
	}
	for {
		var b [1]byte
		_, _ = rand.Read(b[:])
		if id := Templates[int(b[0])%len(Templates)].ID; id != except {
			return id
		}
	}
}

// Pick выбирает заглушку при старте: если в настройках существующая заглушка (в том числе своя страница),
// возвращает её без изменений, иначе (пусто или мусор) случайную. Свою страницу нужно загрузить (SetCustom) до вызова.
func Pick(current string) string {
	if Exists(current) {
		return current
	}
	return RandomID("")
}
