package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"kitsune/internal/check"
	"kitsune/internal/db"
)

// passportLoop раз в несколько часов сам проверяет безопасность и пишет результат в историю:
// так график заполняется, даже если никто не открывает «Здоровье».
func passportLoop() {
	time.Sleep(3 * time.Minute) // даём ядрам запуститься
	for {
		check.RecordPassport()
		time.Sleep(6 * time.Hour)
	}
}

// handlePassportHistory отдаёт историю паспорта безопасности (до 90 дней).
func handlePassportHistory(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"history": db.GetPassport(400)})
}
