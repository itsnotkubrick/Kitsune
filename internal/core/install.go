package core

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Закреплённые версии ядер и контрольные суммы их архивов – запасной вариант, если последний выпуск узнать не удалось.
// Скачанный архив принимается, только если его SHA-256 совпал: зеркалам «на слово» не верим.
const (
	XrayVersion    = "v26.6.27"
	SingboxVersion = "1.14.3"
	MTGVersion     = "2.2.8"
	MitaVersion    = "3.38.1"
	TelemtVersion  = "3.5.14"
	// MasqueVersion – запасная версия sing-box для MASQUE (предрелиз 1.15): ставится, только если последний выпуск узнать не удалось.
	// Обычно панель ставит самый новый выпуск, в том числе предрелиз, поэтому эта цифра нужна лишь как нижняя граница.
	MasqueVersion = "1.15.0-alpha.13"
)

// Asset – архив ядра для платформы.
type Asset struct {
	URL    string
	SHA256 string
}

var xrayAssets = map[string]Asset{
	"linux-amd64":  {"https://github.com/XTLS/Xray-core/releases/download/" + XrayVersion + "/Xray-linux-64.zip", "b3e5902d06d6282fe53cfa2fc426058b9aeaa429b2c812e20887cd47f26d08bf"},
	"linux-arm64":  {"https://github.com/XTLS/Xray-core/releases/download/" + XrayVersion + "/Xray-linux-arm64-v8a.zip", "13a251379bea366c2cf10363ad71e75734193d401f26f518bf0c25e5c8f8c931"},
	"darwin-arm64": {"https://github.com/XTLS/Xray-core/releases/download/" + XrayVersion + "/Xray-macos-arm64-v8a.zip", "5b63cf477b4281dc0d9d3af4d7b87391ab868a842b430e9ce8957ea0b60ecab7"},
}

var singboxAssets = map[string]Asset{
	"linux-amd64":  {"https://github.com/SagerNet/sing-box/releases/download/v" + SingboxVersion + "/sing-box-" + SingboxVersion + "-linux-amd64.tar.gz", "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee"},
	"linux-arm64":  {"https://github.com/SagerNet/sing-box/releases/download/v" + SingboxVersion + "/sing-box-" + SingboxVersion + "-linux-arm64.tar.gz", "29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e"},
	"darwin-arm64": {"https://github.com/SagerNet/sing-box/releases/download/v" + SingboxVersion + "/sing-box-" + SingboxVersion + "-darwin-arm64.tar.gz", "0360ce634a04c26a6b4fd957517987bb4f6c8950f63435ce3c5af2fcae5860c5"},
}

// sing-box для MASQUE: в архиве бинарник называется sing-box, а ставится как sing-box-masque, чтобы не трогать основной sing-box.
var masqueAssets = map[string]Asset{
	"linux-amd64":  {"https://github.com/SagerNet/sing-box/releases/download/v" + MasqueVersion + "/sing-box-" + MasqueVersion + "-linux-amd64.tar.gz", "bfc39f643a5ecc1b702c5723ff662e61dde813f12b3af0d0cfce4f629ff74047"},
	"linux-arm64":  {"https://github.com/SagerNet/sing-box/releases/download/v" + MasqueVersion + "/sing-box-" + MasqueVersion + "-linux-arm64.tar.gz", "6347b1405ec7e1b02fbed77f3b9ae12ba494cc3eb9f47c4adb6877c807a64bf5"},
	"darwin-arm64": {"https://github.com/SagerNet/sing-box/releases/download/v" + MasqueVersion + "/sing-box-" + MasqueVersion + "-darwin-arm64.tar.gz", "fb8d4353e45c985d793b04ccaf2960860128de2c82aa5a00012ce012ab01fc4e"},
}

var mtgAssets = map[string]Asset{
	"linux-amd64":  {"https://github.com/9seconds/mtg/releases/download/v" + MTGVersion + "/mtg-" + MTGVersion + "-linux-amd64.tar.gz", "7ef19d079d85f4e00d4f8334ec1f3f3c8718e3d0ed1f3109ea9a8673138a2102"},
	"linux-arm64":  {"https://github.com/9seconds/mtg/releases/download/v" + MTGVersion + "/mtg-" + MTGVersion + "-linux-arm64.tar.gz", "562a94dd4cafcb8f179b76cfeafb76da12747c8e230bc76235bf8746cc189644"},
	"darwin-arm64": {"https://github.com/9seconds/mtg/releases/download/v" + MTGVersion + "/mtg-" + MTGVersion + "-darwin-arm64.tar.gz", "98af09fb555749aa446d1aec35efc2065ad1ed630abacd5299c703f75cc0cbe6"},
}

// mita (сервер Mieru) существует только для Linux.
var mitaAssets = map[string]Asset{
	"linux-amd64": {"https://github.com/enfein/mieru/releases/download/v" + MitaVersion + "/mita_" + MitaVersion + "_linux_amd64.tar.gz", "015248cd8f9b3b2bc9da2e22f10996952a6ebe782918625a5f26741470a3cae8"},
	"linux-arm64": {"https://github.com/enfein/mieru/releases/download/v" + MitaVersion + "/mita_" + MitaVersion + "_linux_arm64.tar.gz", "3b95221e876ee0bc73b48222b5aa4c91423331ad107a0bba304f88dd044d3abb"},
}

// telemt (MTProto с личными секретами) – статические сборки только для Linux.
var telemtAssets = map[string]Asset{
	"linux-amd64": {"https://github.com/telemt/telemt/releases/download/" + TelemtVersion + "/telemt-x86_64-linux-musl.tar.gz", "71c1454f79cf755edea0985500629daba553002f9863be754e8e38a418822773"},
	"linux-arm64": {"https://github.com/telemt/telemt/releases/download/" + TelemtVersion + "/telemt-aarch64-linux-musl.tar.gz", "21795430c4165cf964405459714d08eea319edaa5c9027beac4de373c356d84d"},
}

var dlClient = &http.Client{Timeout: 10 * time.Minute}

func platform() string { return runtime.GOOS + "-" + runtime.GOARCH }

// openAsset открывает архив ядра. Порядок: папка с готовыми файлами (KITSUNE_CORES_DIR), сам GitHub,
// затем зеркало (KITSUNE_GH_MIRROR – префикс, который ставится перед адресом GitHub). Прокси берётся из HTTPS_PROXY / ALL_PROXY.
// Подлинность это не затрагивает: SHA-256 проверяется после загрузки при любом источнике.
func openAsset(url string) (io.ReadCloser, error) {
	if dir := os.Getenv("KITSUNE_CORES_DIR"); dir != "" {
		if f, err := os.Open(filepath.Join(dir, path.Base(url))); err == nil {
			return f, nil
		}
	}
	try := func(u string) (io.ReadCloser, error) {
		resp, err := dlClient.Get(u)
		if err != nil {
			return nil, fmt.Errorf("загрузка не удалась: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("сервер загрузки ответил %d", resp.StatusCode)
		}
		return resp.Body, nil
	}
	body, err := try(url)
	if err == nil {
		return body, nil
	}
	if m := os.Getenv("KITSUNE_GH_MIRROR"); m != "" {
		if body, err2 := try(strings.TrimRight(m, "/") + "/" + url); err2 == nil {
			return body, nil
		}
	}
	return nil, err
}

// fetchVerified скачивает файл во временный и сверяет SHA-256.
func fetchVerified(a Asset) (string, error) {
	tmp, err := os.CreateTemp("", "kitsune-core-*")
	if err != nil {
		return "", err
	}
	body, err := openAsset(a.URL)
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	defer body.Close()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(body, 200<<20)); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	tmp.Close()
	if hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		os.Remove(tmp.Name())
		return "", errors.New("архив не прошёл проверку SHA-256 – установка отменена")
	}
	return tmp.Name(), nil
}

func install(id string, assets map[string]Asset, name string, wanted map[string]os.FileMode) error {
	return installAs(id, assets, name, wanted, nil)
}

// installAs – install с переименованием файлов при распаковке (имя в архиве -> имя в bin).
func installAs(id string, assets map[string]Asset, name string, wanted map[string]os.FileMode, as map[string]string) error {
	plat := platform()
	pinned, ok := assets[plat]
	if !ok {
		return fmt.Errorf("для платформы %s нет сборки %s", plat, name)
	}
	a, ver := pinned, strings.TrimPrefix(pinnedVersions()[id], "v")
	// Ставим последний выпуск, если ему больше 3 суток; контрольная сумма берётся из описания релиза на GitHub (она защищает от
	// подмены по дороге, но не от взломанного релиза, отсюда карантин). Если последний выпуск получить не удалось или задана папка
	// с готовыми архивами, ставится закреплённая версия, но никогда не старее уже установленной.
	cur := InstalledVersion(id)
	if os.Getenv("KITSUNE_CORES_DIR") == "" && !pinnedForced(id) {
		la, lv, err := latestAsset(id, pinned, freshAllowed(id))
		if err == nil && newerFor(id, cur, lv) {
			err = fmt.Errorf("в репозитории %s, а у вас уже %s", lv, cur)
		}
		if err == nil {
			a, ver = la, lv
		} else if newerFor(id, cur, ver) {
			return fmt.Errorf("%s: последний выпуск не получен (%v), установленная версия %s новее запасной, оставлена как есть", name, err, cur)
		} else {
			log.Printf("%s: последний выпуск недоступен (%v), ставлю закреплённую версию %s", name, err, ver)
		}
	}
	path, err := fetchVerified(a)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	defer os.Remove(path)
	if strings.HasSuffix(a.URL, ".zip") {
		err = extractZip(path, BinDir, wanted)
	} else {
		err = extractTarGzAs(path, BinDir, wanted, as)
	}
	if err == nil {
		setInstalledVersion(id, ver)
	}
	return err
}

// InstallXray, InstallSingbox, InstallMTG, InstallMita кладут бинарники в ./bin.
func InstallXray() error {
	return install("xray", xrayAssets, "Xray", map[string]os.FileMode{"xray": 0o755, "geoip.dat": 0o644, "geosite.dat": 0o644})
}
func InstallSingbox() error {
	// libcronet нужна исходящему naive (клиентская проверка NaiveProxy в «Здоровье»): лежит в архиве рядом с sing-box
	return install("singbox", singboxAssets, "sing-box", map[string]os.FileMode{"sing-box": 0o755, "libcronet.so": 0o755, "libcronet.dylib": 0o755})
}
func InstallMTG() error {
	return install("mtg", mtgAssets, "mtg", map[string]os.FileMode{"mtg": 0o755})
}
func InstallTelemt() error {
	return install("telemt", telemtAssets, "telemt", map[string]os.FileMode{"telemt": 0o755})
}
func InstallMita() error {
	return install("mita", mitaAssets, "mita", map[string]os.FileMode{"mita": 0o755})
}

// InstallMasque ставит sing-box для MASQUE как bin/sing-box-masque (самый новый выпуск, в том числе предрелиз).
func InstallMasque() error {
	return installAs("masque", masqueAssets, "sing-box (MASQUE)", map[string]os.FileMode{"sing-box": 0o755}, map[string]string{"sing-box": "sing-box-masque"})
}

func writeAtomic(dstDir, name string, mode os.FileMode, r io.Reader) error {
	tmp, err := os.CreateTemp(dstDir, ".new-"+name+"-*")
	if err != nil {
		return err
	}
	_, cerr := io.Copy(tmp, io.LimitReader(r, 300<<20))
	tmp.Close()
	if cerr != nil {
		os.Remove(tmp.Name())
		return cerr
	}
	_ = os.Chmod(tmp.Name(), mode)
	if err := os.Rename(tmp.Name(), filepath.Join(dstDir, name)); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

// extractZip достаёт из архива только перечисленные файлы (по имени, без путей).
func extractZip(archive, dstDir string, wanted map[string]os.FileMode) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	found := 0
	for _, f := range zr.File {
		name := filepath.Base(f.Name)
		mode, ok := wanted[name]
		if !ok || f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		err = writeAtomic(dstDir, name, mode, rc)
		rc.Close()
		if err != nil {
			return err
		}
		found++
	}
	if found == 0 {
		return errors.New("в архиве нет нужных файлов")
	}
	return nil
}

func extractTarGz(archive, dstDir string, wanted map[string]os.FileMode) error {
	return extractTarGzAs(archive, dstDir, wanted, nil)
}

// extractTarGzAs достаёт перечисленные файлы; as переименовывает их при записи (имя в архиве -> имя в папке).
func extractTarGzAs(archive, dstDir string, wanted map[string]os.FileMode, as map[string]string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	found := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := filepath.Base(hdr.Name)
		mode, ok := wanted[name]
		if !ok {
			continue
		}
		dst := name
		if n, ok := as[name]; ok {
			dst = n
		}
		if err := writeAtomic(dstDir, dst, mode, tr); err != nil {
			return err
		}
		found++
	}
	if found == 0 {
		return errors.New("в архиве нет нужных файлов")
	}
	return nil
}
