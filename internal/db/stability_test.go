package db

import "testing"

func TestStabilityResults(t *testing.T) {
	t.Chdir(t.TempDir())
	InitDB()
	defer DB.Close()
	tok, err := NewStabilityLink()
	if err != nil || len(tok) != 24 || !StabilityLinkValid(tok) {
		t.Fatalf("ссылка: %q %v", tok, err)
	}
	if StabilityLinkValid("нет-такой") {
		t.Error("чужая ссылка не должна быть действительной")
	}
	if err := AddStabilityResult("нет-такой", "mobile", "", true, 1, 1); err == nil {
		t.Error("результат по чужой ссылке не принимается")
	}
	_ = AddStabilityResult(tok, "mobile", "Оператор <script>", false, 6000, 5200)
	_ = AddStabilityResult(tok, "странный", "", true, 262144, 900)
	res := GetStabilityResults(10)
	if len(res) != 2 || res[1].Kind != "mobile" || res[1].OK || res[0].Kind != "other" || !res[0].OK {
		t.Fatalf("результаты: %+v", res)
	}
	if res[1].Note != "Оператор script" {
		t.Errorf("пометка: %q (кириллица остаётся, угловые скобки убираются)", res[1].Note)
	}
	total, stalled, last := StabilitySummary(7)
	if total != 2 || stalled != 1 || last.Kind != "other" {
		t.Errorf("итог: %d %d %+v", total, stalled, last)
	}
}
