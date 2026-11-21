package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"kitsune/internal/backup"
	"kitsune/internal/core"
	"kitsune/internal/db"
	"kitsune/internal/selfsteal"
)

// handleExportBackup отдаёт резервную копию: база, сертификат и манифест в tar.gz.
// POST с паролем в теле отдаёт копию, зашифрованную этим паролем (пароль в адрес не кладём: он попал бы в журналы).
func handleExportBackup(c *gin.Context) {
	var password string
	if c.Request.Method == http.MethodPost {
		var body struct {
			Password *string `json:"password"`
		}
		decoder := json.NewDecoder(c.Request.Body)
		if err := decoder.Decode(&body); err != nil || body.Password == nil || decoder.Decode(new(json.RawMessage)) != io.EOF {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Укажите пароль копии или передайте пустую строку для экспорта без шифрования"})
			return
		}
		password = *body.Password
	}
	if password != "" && len([]rune(password)) < backup.MinPassLen {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Пароль копии: не меньше %d символов", backup.MinPassLen)})
		return
	}
	stamp := time.Now().Format("20060102-150405")
	var out io.Writer = c.Writer
	var enc io.WriteCloser
	if password != "" {
		var err error
		if enc, err = backup.NewEncryptWriter(c.Writer, password); err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		out = enc
		c.Header("Content-Type", "application/octet-stream")
		c.Header("Content-Disposition", `attachment; filename="kitsune-backup-`+stamp+`.tar.gz.enc"`)
	} else {
		c.Header("Content-Type", "application/gzip")
		c.Header("Content-Disposition", `attachment; filename="kitsune-backup-`+stamp+`.tar.gz"`)
	}
	if err := backup.Write(out); err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	if enc != nil {
		if err := enc.Close(); err != nil {
			return
		}
	}
	_ = db.SetSetting("last_backup", strconv.FormatInt(time.Now().Unix(), 10))
}

// handleRestoreBackup восстанавливает панель из копии (в том числе на новом сервере).
func handleRestoreBackup(c *gin.Context) {
	fh, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Выберите файл резервной копии"})
		return
	}
	f, err := fh.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Не удалось прочитать файл"})
		return
	}
	defer f.Close()
	var src io.Reader = f
	head := make([]byte, 16)
	n, _ := io.ReadFull(f, head)
	src = io.MultiReader(bytes.NewReader(head[:n]), f)
	if backup.IsEncrypted(head[:n]) {
		pw := c.PostForm("password")
		if pw == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Копия защищена паролем: введите пароль копии", "needs_password": true})
			return
		}
		dr, err := backup.NewDecryptReader(src, pw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		src = dr
	}
	res, err := backup.Read(src)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	defer func() { _ = os.Remove(res.DBPath) }() // уже переименована при успехе – Remove тогда ничего не найдёт

	// Страховка: копия текущей базы перед заменой.
	_ = os.MkdirAll("backups", 0o700)
	_ = db.Snapshot("backups/before-restore-" + time.Now().Format("20060102-150405") + ".db")

	if err := db.Replace(res.DBPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось подменить базу: " + err.Error()})
		return
	}

	// Сервер мог смениться: адрес в ссылках и сертификат выпускаются под нынешний.
	moved := ""
	if h := linkHost(c); !isLoopback(h) && res.Manifest.PublicHost != h {
		_ = db.SetSetting("public_host", h)
		backup.RemoveCerts()
		moved = fmt.Sprintf(" Адрес сервера изменился (%s → %s), ссылки и сертификат обновлены.", orDash(res.Manifest.PublicHost), h)
	} else if err := backup.InstallCerts(res.Certs); err != nil {
		moved = " Сертификат из копии восстановить не удалось: выпущен новый."
	}
	// Данные заглушки, своя страница и выбор заглушки пришли из копии: перечитываем их, иначе в памяти останется прежняя страница,
	// а Hysteria и сайт на домене покажут разное.
	initStub()
	selfsteal.Apply()
	msg := "Панель восстановлена из копии (версия " + res.Manifest.Version + ")." + moved + " Войдите заново: логин и пароль теперь из копии."
	// На новом сервере ядер ещё нет: докачиваем те, что нужны подключениям из копии (с проверкой SHA-256).
	inbounds, _ := db.GetInbounds()
	for _, ib := range inbounds {
		if err := core.EnsureForInbound(ib); err != nil {
			msg += " Ядро для " + ib.Tag + " не установлено: " + err.Error() + "."
		}
	}
	if err := applyCores(); err != nil {
		msg += " Ядра применить не удалось: " + err.Error()
	}
	c.JSON(http.StatusOK, gin.H{"message": msg})
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
