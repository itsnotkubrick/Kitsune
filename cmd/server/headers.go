package main

import "github.com/gin-gonic/gin"

// frameHeaders не даёт встроить панель в чужую страницу (clickjacking). Своя вкладка «Роутинг» открывается во фрейме
// того же адреса, поэтому SAMEORIGIN и 'self', а не DENY. Страницы со своими заголовками (подписка) задают их сами позже.
func frameHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Frame-Options", "SAMEORIGIN")
		h.Set("Content-Security-Policy", "frame-ancestors 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		c.Next()
	}
}
