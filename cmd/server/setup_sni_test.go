package main

import (
	"testing"

	"kitsune/internal/proto"
)

func TestPickSecondSNI(t *testing.T) {
	always := func(string) bool { return true }
	cases := []struct {
		name  string
		first string
		cands []string
		works func(string) bool
		want  string
	}{
		{"пропускает первое имя", "a.example.com", []string{"a.example.com", "b.example.com"}, always, "b.example.com"},
		{"регистр и пробелы не мешают", "A.Example.com", []string{" a.example.com ", "B.example.com"}, always, "b.example.com"},
		{"берёт только рабочие", "a.example.com", []string{"x.example.com", "y.example.com"}, func(d string) bool { return d == "y.example.com" }, "y.example.com"},
		{"нет кандидатов", "a.example.com", []string{"a.example.com"}, always, ""},
		{"ничего не подходит", "a.example.com", []string{"x.example.com"}, func(string) bool { return false }, ""},
	}
	for _, c := range cases {
		if got := pickSecondSNI(c.first, c.cands, c.works); got != c.want {
			t.Errorf("%s: получили %q, ждали %q", c.name, got, c.want)
		}
	}
}

func TestQuickSetupKinds(t *testing.T) {
	rec := quickSetupKinds("", "linux")
	if len(rec) != 2 || rec[0] != proto.VlessReality || rec[1] != proto.VlessXHTTP {
		t.Fatalf("рекомендуемый набор: %v", rec)
	}
	if got := quickSetupKinds("recommended", "darwin"); len(got) != 2 {
		t.Fatalf("recommended: %v", got)
	}
	all := quickSetupKinds("all", "linux")
	if len(all) != 11 || all[0] != proto.VlessReality {
		t.Fatalf("полный набор на Linux: %v", all)
	}
	if got := quickSetupKinds("all", "darwin"); len(got) != 9 {
		t.Fatalf("полный набор без AmneziaWG: %v", got)
	}
}
