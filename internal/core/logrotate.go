package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	logMaxSize = 10 << 20            // больше этого размера файл переносится в архив
	logKeep    = 3                   // сколько прежних файлов хранить рядом
	logMaxAge  = 14 * 24 * time.Hour // и не дольше: в журналах бывают адреса и имена сайтов
)

// RotateLogs ограничивает журналы ядер: большой файл копируется в «.1» (старые сдвигаются) и очищается на месте,
// чтобы запущенный процесс продолжал писать в тот же файл; архивы старше срока удаляются.
func RotateLogs(dir string, maxSize int64, keep int, maxAge time.Duration) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.log"))
	for _, f := range files {
		if st, err := os.Stat(f); err == nil && st.Mode().IsRegular() && st.Size() > maxSize {
			rotateOne(f, keep)
		}
	}
	old, _ := filepath.Glob(filepath.Join(dir, "*.log.*"))
	for _, f := range old {
		st, err := os.Stat(f)
		if err != nil {
			continue
		}
		var n int
		if _, e := fmt.Sscanf(f[strings.LastIndex(f, ".")+1:], "%d", &n); e != nil {
			continue // чужие файлы не трогаем
		}
		if n > keep || time.Since(st.ModTime()) > maxAge {
			_ = os.Remove(f)
		}
	}
}

func rotateOne(path string, keep int) {
	for i := keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", path, i), fmt.Sprintf("%s.%d", path, i+1))
	}
	src, err := os.Open(path)
	if err != nil {
		return
	}
	defer src.Close()
	dst, err := os.OpenFile(path+".1", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return
	}
	_, cerr := io.Copy(dst, src)
	dst.Close()
	if cerr == nil {
		_ = os.Truncate(path, 0)
	}
}

// LogMaintenance раз в час приводит журналы в порядок.
func LogMaintenance() {
	RotateLogs(LogDir, logMaxSize, logKeep, logMaxAge)
	for range time.Tick(time.Hour) {
		RotateLogs(LogDir, logMaxSize, logKeep, logMaxAge)
	}
}
