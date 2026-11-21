package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	bodyLimitDefault = 1 << 20   // все обычные запросы панели: JSON в несколько килобайт
	bodyLimitUpload  = 257 << 20 // восстановление копии: файл до 256 МБ плюс поля формы, как у импорта
	readWindow       = 30 * time.Second
	readWindowUpload = 15 * time.Minute
)

// bodyLimit ограничивает размер тела запроса и время на его чтение. Без этого вход и остальные JSON-запросы читают тело без
// предела, а медленная отправка держит соединение. Загрузки (восстановление копии) получают большой предел, а импорт
// выставляет свой сам (api_import.go) и здесь не трогается.
func bodyLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		max, window := int64(bodyLimitDefault), readWindow
		switch c.FullPath() {
		case "/api/v1/import/preview", "/api/v1/import/run":
			window = readWindowUpload
			max = -1 // свой предел в handleImport
		case "/api/v1/backup/restore":
			max, window = bodyLimitUpload, readWindowUpload
		}
		// Ошибка (writer без поддержки дедлайнов, например в тестах) не мешает: тогда остаётся только предел размера.
		_ = http.NewResponseController(c.Writer).SetReadDeadline(time.Now().Add(window))
		if max < 0 {
			c.Next()
			return
		}
		if c.Request.ContentLength > max {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "Запрос слишком большой"})
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, max)
		c.Next()
	}
}
