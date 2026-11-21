// Package backup делает и восстанавливает резервные копии панели: база (пользователи, подключения, ключи)
// и самоподписанный сертификат. Бинарники ядер в копию не входят – они скачиваются заново с проверкой SHA-256.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"kitsune/internal/cert"
	"kitsune/internal/db"
	"kitsune/internal/version"
)

type Manifest struct {
	App        string `json:"app"`
	Version    string `json:"version"`
	Created    int64  `json:"created"`
	PublicHost string `json:"public_host"`
}

// Разрешённые имена в архиве: всё остальное при восстановлении отклоняется.
var allowed = map[string]int64{
	"manifest.json":  1 << 20,
	"kitsune.db":     500 << 20,
	"certs/self.crt": 1 << 20,
	"certs/self.key": 1 << 20,
}

func addFile(tw *tar.Writer, name string, data []byte, mode int64) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data)), ModTime: time.Now(), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// Write пишет копию в w (tar.gz).
func Write(w io.Writer) error {
	tmp, err := os.CreateTemp("", "kitsune-snap-*.db")
	if err != nil {
		return err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	if err := db.Snapshot(tmp.Name()); err != nil {
		return err
	}
	dbData, err := os.ReadFile(tmp.Name())
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	mf, _ := json.Marshal(Manifest{App: "kitsune", Version: version.Version, Created: time.Now().Unix(), PublicHost: db.GetSetting("public_host", "")})
	if err := addFile(tw, "manifest.json", mf, 0o600); err != nil {
		return err
	}
	if err := addFile(tw, "kitsune.db", dbData, 0o600); err != nil {
		return err
	}
	p := cert.SelfPaths()
	for _, f := range []struct{ path, name string }{{p.CertFile, "certs/self.crt"}, {p.KeyFile, "certs/self.key"}} {
		if data, err := os.ReadFile(f.path); err == nil {
			if err := addFile(tw, f.name, data, 0o600); err != nil {
				return err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// Result – что нашлось в архиве после проверки.
type Result struct {
	Manifest Manifest
	DBPath   string
	Certs    map[string][]byte
}

// Read проверяет архив и извлекает базу во временный файл. Никакие пути из архива на диск не попадают.
func Read(r io.Reader) (*Result, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, errors.New("это не резервная копия Kitsune (не tar.gz)")
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	res := &Result{Certs: map[string][]byte{}}
	var haveDB, haveManifest bool
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("архив повреждён")
		}
		limit, ok := allowed[hdr.Name]
		if !ok || hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("в архиве лишний файл %q – это не резервная копия Kitsune", hdr.Name)
		}
		if hdr.Size > limit {
			return nil, fmt.Errorf("файл %q слишком большой", hdr.Name)
		}
		switch hdr.Name {
		case "kitsune.db":
			f, err := os.CreateTemp(".", ".restore-*.db")
			if err != nil {
				return nil, err
			}
			if _, err := io.Copy(f, io.LimitReader(tr, limit+1)); err != nil {
				f.Close()
				os.Remove(f.Name())
				return nil, err
			}
			f.Close()
			_ = os.Chmod(f.Name(), 0o600)
			res.DBPath = f.Name()
			haveDB = true
		case "manifest.json":
			data, _ := io.ReadAll(io.LimitReader(tr, limit))
			if json.Unmarshal(data, &res.Manifest) != nil || res.Manifest.App != "kitsune" {
				return nil, errors.New("это не резервная копия Kitsune (неверный манифест)")
			}
			haveManifest = true
		default:
			data, _ := io.ReadAll(io.LimitReader(tr, limit))
			res.Certs[hdr.Name] = data
		}
	}
	if !haveDB || !haveManifest {
		if res.DBPath != "" {
			os.Remove(res.DBPath)
		}
		return nil, errors.New("в архиве нет базы или манифеста – это не резервная копия Kitsune")
	}
	return res, nil
}

// InstallCerts кладёт сертификат из копии на место.
func InstallCerts(c map[string][]byte) error {
	if len(c) == 0 {
		return nil
	}
	if err := os.MkdirAll(cert.Dir, 0o700); err != nil {
		return err
	}
	for name, data := range c {
		perm := os.FileMode(0o644)
		if filepath.Base(name) == "self.key" {
			perm = 0o600
		}
		if err := os.WriteFile(filepath.Join(cert.Dir, filepath.Base(name)), data, perm); err != nil {
			return err
		}
	}
	return nil
}

// RemoveCerts удаляет самоподписанный сертификат (он выпустится заново на нужный адрес).
func RemoveCerts() {
	p := cert.SelfPaths()
	_ = os.Remove(p.CertFile)
	_ = os.Remove(p.KeyFile)
}
