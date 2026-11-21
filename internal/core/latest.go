package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Репозитории ядер: из них берутся последний выпуск и контрольные суммы архивов.
var coreRepos = map[string]string{
	"xray":    "XTLS/Xray-core",
	"singbox": "SagerNet/sing-box",
	"mtg":     "9seconds/mtg",
	"mita":    "enfein/mieru",
	"telemt":  "telemt/telemt",
	// MASQUE: тот же sing-box, но берётся самый новый выпуск, в том числе предрелиз (в стабильных 1.14 MASQUE нет)
	"masque": "SagerNet/sing-box",
}

// githubAPI заменяется в тестах.
var githubAPI = "https://api.github.com"

const (
	latestTTL     = 6 * time.Hour
	latestFailTTL = 15 * time.Minute
	// Релиз моложе этого срока не ставится: успеют заметить и отозвать взломанный или битый выпуск.
	minReleaseAge = 72 * time.Hour
)

type latestEntry struct {
	tag, published string
	ok             bool
	at             time.Time
}

var latestCache = struct {
	sync.Mutex
	data       map[string]latestEntry
	refreshing bool
}{data: map[string]latestEntry{}}

// Latest – состояние ядра относительно последнего выпуска в его репозитории.
type Latest struct {
	ID          string `json:"id"`
	Pinned      string `json:"pinned"`            // установленная (или закреплённая, если ядро не ставилось) версия
	Verified    string `json:"verified"`          // закреплённая, проверенная нами версия: к ней можно откатиться
	CanRollback bool   `json:"can_rollback"`      // установлена версия, отличная от проверенной
	Latest      string `json:"latest"`            // пусто, если узнать не удалось
	Newer       bool   `json:"newer"`             // в репозитории есть версия новее установленной
	Fresh       bool   `json:"fresh"`             // и ей меньше 3 суток: автоматически не ставится, только вручную с подтверждением
	Warning     string `json:"warning,omitempty"` // что это значит для пользователя
}

func pinnedVersions() map[string]string {
	return map[string]string{"xray": XrayVersion, "singbox": SingboxVersion, "mtg": MTGVersion, "mita": MitaVersion, "telemt": TelemtVersion, "masque": MasqueVersion}
}

func (e latestEntry) fresh() bool {
	ttl := latestTTL
	if !e.ok {
		ttl = latestFailTTL
	}
	return !e.at.IsZero() && time.Since(e.at) < ttl
}

// refreshLatest опрашивает репозитории без удержания блокировки; одновременно идёт только один опрос,
// остальные вызовы получают прежние данные. Контекст не от запроса: отмена страницы не должна кэшировать пустой ответ.
func refreshLatest() {
	latestCache.Lock()
	need := false
	for id := range coreRepos {
		if !latestCache.data[id].fresh() {
			need = true
		}
	}
	if !need || latestCache.refreshing {
		latestCache.Unlock()
		return
	}
	latestCache.refreshing = true
	latestCache.Unlock()

	res := map[string]latestEntry{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for id, repo := range coreRepos {
		wg.Add(1)
		go func(id, repo string) {
			defer wg.Done()
			e := latestEntry{at: time.Now()}
			if r, err := fetchReleaseFor(context.Background(), id, repo); err == nil {
				e.tag, e.published, e.ok = r.Tag, r.newest(""), true
			}
			mu.Lock()
			res[id] = e
			mu.Unlock()
		}(id, repo)
	}
	wg.Wait()
	latestCache.Lock()
	for id, e := range res {
		if !e.ok && latestCache.data[id].ok { // сбой не стирает уже известную версию, но следующая попытка через 15 минут
			old := latestCache.data[id]
			old.at = e.at
			latestCache.data[id] = old
			continue
		}
		latestCache.data[id] = e
	}
	latestCache.refreshing = false
	latestCache.Unlock()
}

// releaseAge – возраст релиза; неизвестная дата считается слишком свежей (карантин).
func releaseAge(published string) (time.Duration, bool) {
	t, err := time.Parse(time.RFC3339, published)
	if err != nil {
		return 0, false
	}
	return time.Since(t), true
}

func quarantined(published string) bool {
	age, ok := releaseAge(published)
	return !ok || age < minReleaseAge
}

// LatestVersions возвращает сравнение установленных версий с последними выпусками. Ответы GitHub кэшируются на 6 часов
// (неудача – на 15 минут); недоступный репозиторий не ошибка, у такого ядра поле Latest пустое.
func LatestVersions(ctx context.Context) []Latest {
	refreshLatest()
	latestCache.Lock()
	data := map[string]latestEntry{}
	for id, e := range latestCache.data {
		data[id] = e
	}
	latestCache.Unlock()

	var out []Latest
	for _, id := range []string{"xray", "singbox", "mtg", "mita", "telemt", "masque"} {
		cur := InstalledVersion(id)
		e := data[id]
		ver := strings.TrimPrefix(pinnedVersions()[id], "v")
		l := Latest{ID: id, Pinned: cur, Verified: ver, CanRollback: cur != "" && ver != "" && strings.TrimPrefix(cur, "v") != ver}
		if e.ok {
			l.Latest = e.tag
			if newerFor(id, e.tag, cur) {
				l.Newer = true
				l.Fresh = quarantined(e.published)
				l.Warning = fmt.Sprintf("Вышла версия %s (установлена %s). Кнопка «Обновить» поставит последнюю.", e.tag, cur)
			}
		}
		out = append(out, l)
	}
	return out
}

type ghRelease struct {
	Tag         string `json:"tag_name"`
	PublishedAt string `json:"published_at"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
	Assets      []struct {
		Name      string `json:"name"`
		Digest    string `json:"digest"` // «sha256:…», GitHub считает при загрузке файла в релиз
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	} `json:"assets"`
}

// newest – самая поздняя из дат релиза и его файлов (для name == "" – всех файлов, иначе только этого).
// Заменить архив в старом релизе так же свежо, как выпустить новый, поэтому в карантин попадает и это.
// Пустая или непонятная дата у файла возвращается как есть, и карантин её отклонит.
func (r *ghRelease) newest(name string) string {
	best, bestT := r.PublishedAt, time.Time{}
	if t, err := time.Parse(time.RFC3339, r.PublishedAt); err == nil {
		bestT = t
	} else {
		return r.PublishedAt
	}
	for _, a := range r.Assets {
		if name != "" && a.Name != name {
			continue
		}
		for _, d := range []string{a.CreatedAt, a.UpdatedAt} {
			t, err := time.Parse(time.RFC3339, d)
			if err != nil {
				return d
			}
			if t.After(bestT) {
				best, bestT = d, t
			}
		}
	}
	return best
}

func fetchRelease(ctx context.Context, repo string) (*ghRelease, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAPI+"/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: %s", resp.Status)
	}
	var r ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&r); err != nil {
		return nil, err
	}
	r.Tag = strings.TrimPrefix(strings.TrimSpace(r.Tag), "v")
	if r.Tag == "" || len(r.Tag) > 40 {
		return nil, fmt.Errorf("пустая версия")
	}
	return &r, nil
}

// fetchReleaseFor возвращает последний выпуск ядра: у MASQUE это самый новый выпуск вместе с предрелизами, у остальных – последний стабильный.
func fetchReleaseFor(ctx context.Context, id, repo string) (*ghRelease, error) {
	if id == "masque" {
		return fetchNewestWithPre(ctx, repo)
	}
	return fetchRelease(ctx, repo)
}

// fetchNewestWithPre выбирает самую высокую версию среди выпусков репозитория, включая предрелизы (черновики пропускаются).
// GitHub отдаёт выпуски по дате, а не по версии, поэтому порядок определяем сами.
func fetchNewestWithPre(ctx context.Context, repo string) (*ghRelease, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAPI+"/repos/"+repo+"/releases?per_page=30", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: %s", resp.Status)
	}
	var list []ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&list); err != nil {
		return nil, err
	}
	var best *ghRelease
	for i := range list {
		r := &list[i]
		r.Tag = strings.TrimPrefix(strings.TrimSpace(r.Tag), "v")
		if r.Draft || r.Tag == "" || len(r.Tag) > 40 {
			continue
		}
		if best == nil || versionCmp(r.Tag, best.Tag) > 0 {
			best = r
		}
	}
	if best == nil {
		return nil, fmt.Errorf("пустая версия")
	}
	return best, nil
}

// parseVer разбирает версию вида 1.15.0-alpha.13: числовая часть и признаки предрелиза.
func parseVer(v string) ([]int, []string) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	core, pre, _ := strings.Cut(v, "-")
	core, _, _ = strings.Cut(core, "+")
	var nums []int
	for _, p := range strings.Split(core, ".") {
		n, _ := strconv.Atoi(p)
		nums = append(nums, n)
	}
	var ids []string
	if pre != "" {
		ids = strings.Split(pre, ".")
	}
	return nums, ids
}

// versionCmp сравнивает версии с предрелизами по правилам semver: 1.15.0 новее 1.15.0-rc.1, а оно новее 1.15.0-alpha.13;
// части предрелиза, состоящие из цифр, сравниваются как числа (alpha.13 новее alpha.9).
func versionCmp(a, b string) int {
	na, pa := parseVer(a)
	nb, pb := parseVer(b)
	for i := 0; i < len(na) || i < len(nb); i++ {
		var x, y int
		if i < len(na) {
			x = na[i]
		}
		if i < len(nb) {
			y = nb[i]
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	switch {
	case len(pa) == 0 && len(pb) == 0:
		return 0
	case len(pa) == 0:
		return 1
	case len(pb) == 0:
		return -1
	}
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, ex := strconv.Atoi(pa[i])
		y, ey := strconv.Atoi(pb[i])
		switch {
		case ex == nil && ey == nil:
			if x != y {
				if x > y {
					return 1
				}
				return -1
			}
		case ex == nil: // число меньше слова
			return -1
		case ey == nil:
			return 1
		default:
			if c := strings.Compare(pa[i], pb[i]); c != 0 {
				return c
			}
		}
	}
	switch {
	case len(pa) > len(pb):
		return 1
	case len(pa) < len(pb):
		return -1
	}
	return 0
}

// newerFor: версия a новее b. У MASQUE версии с предрелизом сравниваются по semver, у остальных – по прежним правилам.
func newerFor(id, a, b string) bool {
	if id == "masque" {
		return versionCmp(a, b) > 0
	}
	return versionNewer(a, b)
}

// latestAsset находит в последнем релизе архив, соответствующий закреплённому (то же имя с новой версией),
// и берёт его SHA-256 из описания релиза.
func latestAsset(id string, pinned Asset, allowFresh bool) (Asset, string, error) {
	repo, ok := coreRepos[id]
	if !ok {
		return Asset{}, "", fmt.Errorf("нет репозитория")
	}
	r, err := fetchReleaseFor(context.Background(), id, repo)
	if err != nil {
		return Asset{}, "", err
	}
	old := strings.TrimPrefix(pinnedVersions()[id], "v")
	url := strings.ReplaceAll(pinned.URL, old, r.Tag)
	name := url[strings.LastIndex(url, "/")+1:]
	for _, a := range r.Assets {
		if a.Name == name {
			if !allowFresh && quarantined(r.newest(name)) {
				return Asset{}, "", fmt.Errorf("релиз %s или файл %s изменён меньше 3 суток назад", r.Tag, name)
			}
			sum := strings.TrimPrefix(a.Digest, "sha256:")
			if len(sum) != 64 || sum == a.Digest {
				return Asset{}, "", fmt.Errorf("у %s в релизе нет контрольной суммы", name)
			}
			return Asset{URL: url, SHA256: strings.ToLower(sum)}, r.Tag, nil
		}
	}
	return Asset{}, "", fmt.Errorf("в релизе %s нет файла %s", r.Tag, name)
}

// Какая версия ядра установлена: запись рядом с бинарником (её пишет установщик панели).
var versionDir = BinDir

func versionFile(id string) string { return filepath.Join(versionDir, id+".version") }

func setInstalledVersion(id, v string) { _ = os.WriteFile(versionFile(id), []byte(v+"\n"), 0o644) }

// InstalledVersion – версия, поставленная панелью; без записи (ядро поставлено раньше или руками) считается закреплённой.
func InstalledVersion(id string) string {
	// Xray могли заменить руками (откат, свой бинарник): запись о версии тогда устарела, верить надо самому файлу.
	if id == "xray" {
		if v := xrayBinaryVersion(); v != "" {
			return v
		}
	}
	if b, err := os.ReadFile(versionFile(id)); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" && len(v) <= 40 {
			return v
		}
	}
	return strings.TrimPrefix(pinnedVersions()[id], "v")
}

// versionNewer сравнивает версии вида 1.2.3 по числам; хвосты вроде -rc1 отбрасываются, версия с хвостом не считается новее.
func versionNewer(a, b string) bool {
	if strings.ContainsAny(a, "-+") {
		return false
	}
	pa, pb := strings.Split(a, "."), strings.Split(strings.SplitN(b, "-", 2)[0], ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x > y
		}
	}
	return false
}

// freshFor – ядра, которым владелец разрешил поставить свежий выпуск (младше карантина) в этой установке.
var freshFor = struct {
	sync.Mutex
	ids map[string]bool
}{ids: map[string]bool{}}

func freshAllowed(id string) bool {
	freshFor.Lock()
	defer freshFor.Unlock()
	return freshFor.ids[id]
}

// InstallComponentFresh ставит ядро так же, как InstallComponent, но выпуск младше 3 суток не отклоняет.
// Остальное не меняется: сумма из релиза, отказ от понижения версии. Решение принимает человек в интерфейсе.
func InstallComponentFresh(id string) error {
	freshFor.Lock()
	freshFor.ids[id] = true
	freshFor.Unlock()
	defer func() { freshFor.Lock(); delete(freshFor.ids, id); freshFor.Unlock() }()
	return InstallComponent(id)
}

// pinnedOnly – ядра, которые сейчас ставятся строго в закреплённой версии (откат), без поиска последнего выпуска.
var pinnedOnly = struct {
	sync.Mutex
	ids map[string]bool
}{ids: map[string]bool{}}

func pinnedForced(id string) bool {
	pinnedOnly.Lock()
	defer pinnedOnly.Unlock()
	return pinnedOnly.ids[id]
}

// InstallComponentPinned возвращает ядро к проверенной (закреплённой) версии, даже если она старее установленной.
// Контрольная сумма берётся из зашитой в Kitsune таблицы, а не из релиза на GitHub.
func InstallComponentPinned(id string) error {
	pinnedOnly.Lock()
	pinnedOnly.ids[id] = true
	pinnedOnly.Unlock()
	defer func() { pinnedOnly.Lock(); delete(pinnedOnly.ids, id); pinnedOnly.Unlock() }()
	return InstallComponent(id)
}

// xrayBinaryVersion спрашивает версию у самого бинарника Xray; ответ кэшируется до смены файла.
var xrayVerCache = struct {
	sync.Mutex
	path string
	mod  time.Time
	size int64
	ver  string
}{}

func xrayBinaryVersion() string {
	bin := XrayBinary()
	if bin == "" {
		return ""
	}
	st, err := os.Stat(bin)
	if err != nil {
		return ""
	}
	xrayVerCache.Lock()
	defer xrayVerCache.Unlock()
	if xrayVerCache.path == bin && xrayVerCache.mod.Equal(st.ModTime()) && xrayVerCache.size == st.Size() {
		return xrayVerCache.ver
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "version").Output()
	ver := ""
	if err == nil {
		if f := strings.Fields(strings.SplitN(string(out), "\n", 2)[0]); len(f) >= 2 {
			ver = strings.TrimPrefix(f[1], "v")
		}
	}
	xrayVerCache.path, xrayVerCache.mod, xrayVerCache.size, xrayVerCache.ver = bin, st.ModTime(), st.Size(), ver
	return ver
}
