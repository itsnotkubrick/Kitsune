//go:build !pro

package web

import "embed"

// ProFS в публичной сборке пуст.
var ProFS embed.FS
