package main

import (
	"testing"
	"time"

	"kitsune/internal/check"
)

func stepsFor(gate chan struct{}) func(bool) []check.Step {
	return func(deep bool) []check.Step {
		s := []check.Step{
			{ID: "a", Group: "Первая", Do: func() []check.Item { return []check.Item{{Group: "Первая", Level: check.OK, Text: "ок"}} }},
			{ID: "b", Group: "Вторая", Do: func() []check.Item {
				<-gate
				return []check.Item{{Group: "Вторая", Level: check.Warn, Text: "внимание"}}
			}},
			{ID: "c", Group: "Третья", Do: func() []check.Item {
				return []check.Item{{Group: "Третья", Level: check.Bad, Text: "плохо"}}
			}},
		}
		if deep {
			s = append(s, check.Step{ID: "deep", Group: "Глубокая", Do: func() []check.Item { return nil }})
		}
		return s
	}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("не дождались: %s", what)
}

func stateOf(j *healthJob) []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	var s []string
	for _, st := range j.steps {
		s = append(s, st.ID+":"+st.State)
	}
	return s
}

// Прогон идёт по шагам: ещё не начатые pending, текущий running, готовые done; итоговый отчёт появляется в конце.
func TestHealthJobProgress(t *testing.T) {
	old := healthSteps
	defer func() { healthSteps = old }()
	gate := make(chan struct{})
	healthSteps = stepsFor(gate)
	var j healthJob
	seq, started := j.start(false)
	if !started || seq != 1 {
		t.Fatalf("start: %d %v", seq, started)
	}
	waitFor(t, func() bool {
		s := stateOf(&j)
		return len(s) == 3 && s[0] == "a:done" && s[1] == "b:running" && s[2] == "c:pending"
	}, "a готов, b идёт, c ждёт")
	snap := j.snapshot()
	if snap["running"] != true || snap["report"] != nil {
		t.Fatalf("пока идёт, отчёта быть не должно: %+v", snap)
	}
	if _, again := j.start(false); again {
		t.Fatal("второй запуск во время прогона не должен стартовать")
	}
	close(gate)
	waitFor(t, func() bool { j.mu.Lock(); defer j.mu.Unlock(); return !j.running && j.report != nil }, "конец прогона")
	if j.report.Bad != 1 || j.report.Warn != 1 || len(j.report.Items) != 3 {
		t.Fatalf("отчёт: %+v", j.report)
	}
	for _, st := range j.snapshot()["steps"].([]healthStep) {
		if st.State != "done" || len(st.Items) != 1 {
			t.Errorf("шаг %+v", st)
		}
	}
}

// Каждый запуск идёт заново: новый номер, шаги снова pending, прежний отчёт сброшен.
func TestHealthJobRestartsFresh(t *testing.T) {
	old := healthSteps
	defer func() { healthSteps = old }()
	gate := make(chan struct{})
	close(gate)
	healthSteps = stepsFor(gate)
	var j healthJob
	j.start(false)
	waitFor(t, func() bool { j.mu.Lock(); defer j.mu.Unlock(); return !j.running }, "первый прогон")
	gate2 := make(chan struct{})
	healthSteps = stepsFor(gate2)
	seq, started := j.start(true)
	if !started || seq != 2 {
		t.Fatalf("второй запуск: %d %v", seq, started)
	}
	if snap := j.snapshot(); snap["report"] != nil || len(snap["steps"].([]healthStep)) != 4 || snap["deep"] != true {
		t.Fatalf("после перезапуска: %+v", snap)
	}
	close(gate2)
	waitFor(t, func() bool { j.mu.Lock(); defer j.mu.Unlock(); return !j.running }, "второй прогон")
}

func TestHealthJobEmptyBeforeFirstRun(t *testing.T) {
	var j healthJob
	snap := j.snapshot()
	if snap["running"] != false || len(snap["steps"].([]healthStep)) != 0 {
		t.Fatalf("%+v", snap)
	}
}
