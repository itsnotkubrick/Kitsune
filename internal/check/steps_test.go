package check

import "testing"

func TestStepsAreUniqueAndNamed(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range Steps() {
		if s.ID == "" || s.Group == "" || s.Do == nil || seen[s.ID] {
			t.Fatalf("шаг %+v", s)
		}
		seen[s.ID] = true
	}
	if len(seen) < 10 {
		t.Fatalf("шагов %d", len(seen))
	}
}

func TestBuildCountsAndStepResult(t *testing.T) {
	r := Build([]Item{{Level: OK}, {Level: Warn}, {Level: Bad}, {Level: Bad}, {Level: Info}})
	if r.Bad != 2 || r.Warn != 1 || len(r.Items) != 5 {
		t.Fatalf("%+v", r)
	}
	res := Step{ID: "x", Group: "g", Do: func() []Item { return []Item{{Level: OK}} }}.Execute()
	if len(res.Items) != 1 || res.Millis < 0 {
		t.Fatalf("%+v", res)
	}
}
