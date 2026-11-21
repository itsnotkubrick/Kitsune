package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"kitsune/internal/check"
	"kitsune/internal/update"
	"kitsune/internal/version"

	"github.com/gin-gonic/gin"
)

// Обновления идут из GitHub Latest Release тем же путём, что и «kit → Обновить»: install.sh update скачивает сборку
// и проверяет подпись и SHA-256. Панель только узнаёт, что вышла новая версия, и запускает этот установщик.
// Если задан KITSUNE_UPDATE_URL (разработка), используется старый путь через манифест.

var (
	updMu     sync.Mutex
	updCached *update.Info
	updErr    string
)

func useManifest() bool { return os.Getenv("KITSUNE_UPDATE_URL") != "" }

func init() {
	// проверка здоровья спрашивает версию тем же путём, что и кнопка обновления
	check.PanelUpdate = func() (string, bool, error) {
		if useManifest() {
			u, key := update.Source()
			info, err := update.Check(u, version.Version, key)
			if err != nil {
				return "", false, err
			}
			return info.Latest, info.Available, nil
		}
		info, err := checkRelease()
		if err != nil {
			return "", false, err
		}
		return info.Latest, info.Available, nil
	}
}

func checkRelease() (*update.Info, error) {
	return update.CheckRelease(os.Getenv("KITSUNE_BASE_URL"), version.Version)
}

// updateWatcher раз в 6 часов спрашивает, не вышла ли новая версия, и запоминает ответ для всплывающего уведомления.
func updateWatcher() {
	if useManifest() {
		return
	}
	time.Sleep(time.Minute)
	for {
		info, err := checkRelease()
		updMu.Lock()
		if err != nil {
			updErr = err.Error()
		} else {
			updCached, updErr = info, ""
		}
		updMu.Unlock()
		time.Sleep(6 * time.Hour)
	}
}

func handleUpdateStatus(c *gin.Context) {
	updMu.Lock()
	defer updMu.Unlock()
	if updCached == nil {
		c.JSON(http.StatusOK, gin.H{"available": false, "current": version.Version})
		return
	}
	c.JSON(http.StatusOK, gin.H{"available": updCached.Available, "latest": updCached.Latest, "current": version.Version})
}

func handleUpdateCheck(c *gin.Context) {
	if useManifest() {
		u, key := update.Source()
		info, err := update.Check(u, version.Version, key)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error(), "current": version.Version})
			return
		}
		c.JSON(http.StatusOK, gin.H{"info": info, "current": version.Version})
		return
	}
	info, err := checkRelease()
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error(), "current": version.Version})
		return
	}
	updMu.Lock()
	updCached = info
	updMu.Unlock()
	info.Signed = true // подпись проверяет установщик
	c.JSON(http.StatusOK, gin.H{"info": info, "current": version.Version})
}

func handleUpdateApply(c *gin.Context) {
	if _, err := check.MakeBackup(); err != nil {
		log.Printf("Не удалось сделать копию базы перед обновлением: %v", err)
	}
	if useManifest() {
		u, key := update.Source()
		v, err := update.Apply(u, version.Version, key)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Версия " + v + " установлена. Панель перезапускается, страница обновится через несколько секунд.", "version": v})
		return
	}
	script := installScript()
	if _, err := os.Stat(script); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "не найден установщик " + script + ": обновите командой kit на сервере"})
		return
	}
	wd, _ := os.Getwd()
	args := []string{script, "update", "--dir", wd, "--yes"}
	var cmd *exec.Cmd
	// Отдельная временная служба: установщик перезапускает kitsune, и вместе с ней не должен погибнуть сам.
	if p, err := exec.LookPath("systemd-run"); err == nil {
		cmd = exec.Command(p, append([]string{"--unit=kitsune-update", "--collect", "bash"}, args...)...)
	} else {
		cmd = exec.Command("setsid", append([]string{"bash"}, args...)...)
	}
	if f, err := os.OpenFile(filepath.Join(wd, "update.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err == nil {
		cmd.Stdout, cmd.Stderr = f, f
	}
	if lf, ok := cmd.Stdout.(*os.File); ok {
		defer lf.Close() // дочерний процесс уже получил свой дескриптор
	}
	if err := cmd.Start(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("не удалось запустить обновление: %v", err)})
		return
	}
	go cmd.Wait()
	c.JSON(http.StatusOK, gin.H{"message": "Обновление запущено: установщик скачивает и проверяет новую версию. Панель перезапустится, страница обновится через минуту. Ход обновления: update.log в каталоге панели."})
}
