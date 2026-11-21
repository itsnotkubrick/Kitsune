package importer

import (
	"os"
	"path/filepath"
	"time"
)

// CleanTempMinAge – минимальный возраст папки для уборки при старте: свежие могут принадлежать идущему импорту из консоли.
var CleanTempMinAge = time.Hour

// TempDirName – каталог для временных копий чужих баз и загрузок. Лежит в каталоге данных установки
// (рядом с kitsune.db), то есть на диске, а не в /tmp, который на многих системах живёт в памяти.
const TempDirName = "import-tmp"

// TempRoot создаёт каталог временных файлов с правами 700 (права выправляются, если папка уже была) и возвращает путь.
func TempRoot() (string, error) {
	if err := os.MkdirAll(TempDirName, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(TempDirName, 0o700); err != nil {
		return "", err
	}
	return TempDirName, nil
}

// CleanTemp удаляет остатки прерванных загрузок и импортов (вызывается при старте панели, когда импорта ещё нет).
// Трогает только папки kitsune-import-* и kitsune-upload-* внутри нашего каталога и только старше CleanTempMinAge.
func CleanTemp() {
	cutoff := time.Now().Add(-CleanTempMinAge)
	for _, pat := range []string{"kitsune-import-*", "kitsune-upload-*"} {
		m, _ := filepath.Glob(filepath.Join(TempDirName, pat))
		for _, p := range m {
			if st, err := os.Lstat(p); err == nil && st.IsDir() && !st.ModTime().After(cutoff) {
				_ = os.RemoveAll(p)
			}
		}
	}
}
