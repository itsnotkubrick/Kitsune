package core

import (
	"strconv"
	"sync"
	"testing"
)

// Карта процессов MTProto: применение конфигурации пишет её, обработчики HTTP (Statuses) и остановка читают.
// Тест имеет смысл под -race: без замка здесь была бы гонка (и падение «concurrent map iteration and map write»).
func TestMTGProcsConcurrentAccess(t *testing.T) {
	t.Cleanup(func() { mtgDrop(map[string]bool{}) })
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			for n := 0; n < 200; n++ {
				name := "mtg-" + strconv.Itoa((i*7+n)%5)
				mtgProc(name)
				mtgDrop(map[string]bool{name: true})
			}
		}(i)
		go func() {
			defer wg.Done()
			for n := 0; n < 200; n++ {
				_ = Statuses()
				_ = anyRunning()
				_ = mtgList()
			}
		}()
	}
	wg.Wait()
}

func TestMTGDropKeepsWanted(t *testing.T) {
	t.Cleanup(func() { mtgDrop(map[string]bool{}) })
	a, b := mtgProc("mtg-1"), mtgProc("mtg-2")
	if mtgProc("mtg-1") != a {
		t.Fatal("повторный вызов вернул другой процесс")
	}
	gone := mtgDrop(map[string]bool{"mtg-1": true})
	if len(gone) != 1 || gone["mtg-2"] != b {
		t.Fatalf("убран не тот процесс: %v", gone)
	}
	if l := mtgList(); len(l) != 1 || l[0] != a {
		t.Fatalf("в списке должен остаться только mtg-1, а там %d", len(l))
	}
}
