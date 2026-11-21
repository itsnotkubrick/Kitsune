package main

import (
	"sort"
	"sync"
	"time"
)

// Защита ссылок подписки от перебора: после subMaxFails запросов с несуществующим идентификатором
// адрес на окно loginWindow получает на все запросы к /sub/ обычный 404, как у любого неизвестного адреса
// (в том числе с верным идентификатором, чтобы ответ не подсказывал, угадан ли он). Ключ адреса тот же, что у лимита входа: IPv6 по сети /64.
// Адрес берётся из c.ClientIP(), то есть X-Forwarded-For учитывается только от доверенных прокси.
const (
	subMaxFails = 30
	subTableMax = 4096
)

var (
	subMu    sync.Mutex
	subFails = map[string][]time.Time{}
)

// subRecent оставляет неудачи за окно (вызывать под замком).
func subRecent(key string) []time.Time {
	cutoff := time.Now().Add(-loginWindow)
	list := subFails[key][:0]
	for _, t := range subFails[key] {
		if t.After(cutoff) {
			list = append(list, t)
		}
	}
	if len(list) == 0 {
		delete(subFails, key)
	} else {
		subFails[key] = list
	}
	return list
}

// subBlocked – адрес исчерпал лимит неудачных запросов.
func subBlocked(ip string) bool {
	key := loginKey(ip)
	subMu.Lock()
	defer subMu.Unlock()
	return len(subRecent(key)) >= subMaxFails
}

// subFail запоминает запрос с несуществующим идентификатором.
func subFail(ip string) {
	key := loginKey(ip)
	subMu.Lock()
	defer subMu.Unlock()
	if _, known := subFails[key]; !known && len(subFails) >= subTableMax {
		pruneSubFails()
	}
	subFails[key] = append(subFails[key], time.Now())
}

// pruneSubFails убирает устаревшее, а если места всё равно нет – четверть самых давних адресов.
func pruneSubFails() {
	type entry struct {
		key  string
		last time.Time
	}
	items := make([]entry, 0, len(subFails))
	for k := range subFails {
		if l := subRecent(k); len(l) > 0 {
			items = append(items, entry{k, l[len(l)-1]})
		}
	}
	if len(subFails) < subTableMax {
		return
	}
	sort.Slice(items, func(i, j int) bool { return items[i].last.Before(items[j].last) })
	for i := 0; i < subTableMax/4 && i < len(items); i++ {
		delete(subFails, items[i].key)
	}
}
