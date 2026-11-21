// Package servertest – тесты нового сервера до развёртывания: подходит ли VPS для прокси (процессор, диск, память, сеть).
// Каждый тест возвращает результат со статусом и подсказкой; сводка «подходит / с оговорками / не подходит» считается по ним.
// Здесь только то, что работает без внешних запросов: проверки с внешними сервисами требуют согласия пользователя и идут отдельным шагом.
package servertest

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Level – статус результата.
type Level string

const (
	OK   Level = "ok"
	Warn Level = "warn"
	Bad  Level = "bad"
	Info Level = "info" // справочная строка, на сводку не влияет
	Skip Level = "skip" // тест пропущен (платформа, отсутствие согласия), на сводку не влияет
)

// Lang – язык текстов результата: панель показывает русский, консоль kit английский.
type Lang string

const (
	RU Lang = "ru"
	EN Lang = "en"
)

// L выбирает текст по языку.
func L(l Lang, ru, en string) string {
	if l == EN {
		return en
	}
	return ru
}

// Result – итог одного теста.
type Result struct {
	ID     string `json:"id"`
	Group  string `json:"group"`
	Level  Level  `json:"level"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"` // измеренные значения
	Hint   string `json:"hint,omitempty"`   // что делать, если не ok
	Millis int64  `json:"millis"`
}

// Test – один тест. External помечает тесты, которым нужен внешний сервис (и согласие пользователя), Heavy – тяжёлые.
type Test struct {
	ID       string
	Group    string
	External bool
	Heavy    bool // заметно нагружает сервер или сеть: в панели запускается только по явному подтверждению
	Timeout  time.Duration
	Run      func(ctx context.Context, l Lang) Result
}

// Report – результаты прогона и сводка.
type Report struct {
	Results  []Result `json:"results"`
	Verdict  string   `json:"verdict"` // ok, caveats, bad
	Started  int64    `json:"started"`
	Finished int64    `json:"finished"`
}

// Verdict считает сводку: хоть один bad – «не подходит», иначе хоть один warn – «с оговорками».
func Verdict(rs []Result) string {
	v := "ok"
	for _, r := range rs {
		switch r.Level {
		case Bad:
			return "bad"
		case Warn:
			v = "caveats"
		}
	}
	return v
}

// VerdictText – фраза сводки.
func VerdictText(v string, l Lang) string {
	switch v {
	case "bad":
		return L(l, "Сервер не подходит: есть критичные проблемы", "Not suitable: there are critical problems")
	case "caveats":
		return L(l, "Подходит с оговорками: см. предупреждения", "Suitable with caveats: see the warnings")
	}
	return L(l, "Сервер подходит", "The server is suitable")
}

// Run выполняет тесты по очереди: у каждого свой таймаут, паника теста не роняет прогон, отмена контекста останавливает остальные.
// onResult вызывается после каждого теста (для прогресса).
func Run(ctx context.Context, tests []Test, l Lang, onResult func(Result)) Report {
	rep := Report{Started: time.Now().Unix()}
	for _, t := range tests {
		if ctx.Err() != nil {
			break
		}
		r := runOne(ctx, t, l)
		rep.Results = append(rep.Results, r)
		if onResult != nil {
			onResult(r)
		}
	}
	sort.SliceStable(rep.Results, func(i, j int) bool { return false }) // порядок прогона сохраняется
	rep.Verdict = Verdict(rep.Results)
	rep.Finished = time.Now().Unix()
	return rep
}

func runOne(ctx context.Context, t Test, l Lang) (res Result) {
	to := t.Timeout
	if to <= 0 {
		to = 15 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	start := time.Now()
	defer func() {
		if p := recover(); p != nil {
			res = Result{ID: t.ID, Group: t.Group, Level: Warn, Title: t.ID, Detail: fmt.Sprint("panic: ", p), Hint: L(l, "Тест завершился сбоем и пропущен.", "The test crashed and was skipped.")}
		}
		res.Millis = time.Since(start).Milliseconds()
		if res.ID == "" {
			res.ID = t.ID
		}
		if res.Group == "" {
			res.Group = t.Group
		}
	}()
	done := make(chan Result, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				done <- Result{ID: t.ID, Group: t.Group, Level: Warn, Title: t.ID, Detail: fmt.Sprint("panic: ", p), Hint: L(l, "Тест завершился сбоем и пропущен.", "The test crashed and was skipped.")}
			}
		}()
		done <- t.Run(cctx, l)
	}()
	select {
	case r := <-done:
		return r
	case <-cctx.Done():
		return Result{ID: t.ID, Group: t.Group, Level: Warn, Title: t.ID, Detail: cctx.Err().Error(), Hint: L(l, "Тест не уложился во время и остановлен.", "The test did not finish in time and was stopped.")}
	}
}
