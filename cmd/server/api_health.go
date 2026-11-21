package main

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"kitsune/internal/check"
)

// Проверка здоровья в реальном времени: каждый запуск заново выполняет все шаги по одному, панель опрашивает состояние
// и показывает, какой шаг идёт сейчас и сколько занял каждый уже выполненный.

type healthStep struct {
	ID     string       `json:"id"`
	Group  string       `json:"group"`
	State  string       `json:"state"` // pending, running, done
	Millis int64        `json:"millis"`
	Items  []check.Item `json:"items,omitempty"`
}

type healthJob struct {
	mu      sync.Mutex
	seq     int
	running bool
	deep    bool
	started time.Time
	steps   []healthStep
	report  *check.Report
}

var hjob healthJob

// healthSteps – шаги прогона; в тестах подменяется.
var healthSteps = func(deep bool) []check.Step {
	steps := check.Steps()
	if deep {
		steps = append(steps, check.Step{ID: "deep", Group: "Живая проверка подключений", Do: func() []check.Item { return check.Deep().Items }})
	}
	return steps
}

// start запускает новый прогон. Если предыдущий ещё идёт, новый не запускается (started=false), опрашивать можно текущий.
func (j *healthJob) start(deep bool) (seq int, started bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.running {
		return j.seq, false
	}
	steps := healthSteps(deep)
	j.seq++
	j.running, j.deep, j.started, j.report = true, deep, time.Now(), nil
	j.steps = make([]healthStep, len(steps))
	for i, s := range steps {
		j.steps[i] = healthStep{ID: s.ID, Group: s.Group, State: "pending"}
	}
	seq = j.seq
	go func() {
		var all []check.Item
		for i, s := range steps {
			j.mu.Lock()
			j.steps[i].State = "running"
			j.mu.Unlock()
			res := s.Execute()
			j.mu.Lock()
			j.steps[i].State, j.steps[i].Millis, j.steps[i].Items = "done", res.Millis, res.Items
			j.mu.Unlock()
			all = append(all, res.Items...)
		}
		rep := check.Build(all)
		j.mu.Lock()
		j.running, j.report = false, &rep
		j.mu.Unlock()
	}()
	return seq, true
}

func (j *healthJob) snapshot() gin.H {
	j.mu.Lock()
	defer j.mu.Unlock()
	steps := append([]healthStep{}, j.steps...)
	h := gin.H{"seq": j.seq, "running": j.running, "deep": j.deep, "steps": steps, "elapsed_ms": 0}
	if !j.started.IsZero() {
		h["elapsed_ms"] = time.Since(j.started).Milliseconds()
	}
	if j.report != nil {
		h["report"] = j.report
	}
	return h
}

func handleHealthStart(c *gin.Context) {
	seq, started := hjob.start(c.Query("deep") == "1")
	c.JSON(http.StatusAccepted, gin.H{"seq": seq, "started": started})
}

func handleHealthJob(c *gin.Context) { c.JSON(http.StatusOK, hjob.snapshot()) }
