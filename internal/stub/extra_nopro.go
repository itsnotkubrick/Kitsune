//go:build !pro && !closed

package stub

// Точки подключения дополнительных страниц; в этой сборке они пусты.

func extraHTML(string) (string, bool)   { return "", false }
func extraHas(string) bool              { return false }
func extraTitle(string) (string, bool)  { return "", false }
func extraRandom(string) (string, bool) { return "", false }
