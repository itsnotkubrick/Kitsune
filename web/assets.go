package web

import (
	"embed"
)

//go:embed index.html
var IndexHTML []byte

//go:embed logo.png
var LogoPNG []byte

//go:embed logo_text.png
var LogoTextPNG []byte

//go:embed all:tools
var ToolsFS embed.FS

//go:embed all:static
var StaticFS embed.FS
