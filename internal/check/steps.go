package check

import "time"

// Step – одна проверка (группа отчёта). Шаги выполняются по одному, поэтому панель показывает ход проверки в реальном времени,
// а Run собирает тот же отчёт, что и раньше.
type Step struct {
	ID    string
	Group string
	Do    func() []Item // выполняет проверку и возвращает её строки
}

// StepResult – итог шага: строки, время выполнения и счётчики.
type StepResult struct {
	Items  []Item
	Millis int64
}

// collect выполняет проверки и собирает их строки.
func collect(fns ...func(add adder)) []Item {
	var items []Item
	add := func(group, level, text, fix string) {
		items = append(items, Item{Group: group, Level: level, Text: text, Fix: fix, FixTip: fixTipFor(fix)})
	}
	for _, f := range fns {
		f(add)
	}
	return items
}

// Steps – проверки по порядку выполнения; название группы то же, что в строках отчёта.
func Steps() []Step {
	mk := func(id, group string, fns ...func(add adder)) Step {
		return Step{ID: id, Group: group, Do: func() []Item { return collect(fns...) }}
	}
	return []Step{
		mk("services", "Службы", checkServices),
		mk("config", "Конфигурация", checkConfig),
		mk("ports", "Подключения", checkPorts, checkInboundsExtra),
		mk("path", pathGroup, checkPath),
		mk("firewall", "Файрвол", checkFirewall),
		mk("db", "База данных", checkDB),
		mk("clients", "Клиенты", checkClients, checkClientsExtra),
		mk("resources", "Ресурсы сервера", checkResources),
		mk("network", "Сеть", checkNetwork),
		mk("security", "Безопасность", checkPerms, checkSecurity),
		{ID: "posture", Group: postureGroup, Do: postureItems},
		mk("time", "Система", checkTime),
		mk("backup", "Резервные копии", checkBackup),
		mk("updates", "Обновления", checkUpdates),
	}
}

// Execute выполняет шаг и замеряет время.
func (s Step) Execute() StepResult {
	t := time.Now()
	items := s.Do()
	return StepResult{Items: items, Millis: time.Since(t).Milliseconds()}
}

// Build собирает отчёт из строк шагов (с исправлениями).
func Build(items []Item) Report {
	r := Report{Items: items}
	for _, it := range items {
		switch it.Level {
		case Bad:
			r.Bad++
		case Warn:
			r.Warn++
		}
	}
	return r.WithFixes()
}
