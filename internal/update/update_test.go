package update

import "testing"

func TestNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0.2", "0.1-pre-release", true},
		{"0.1.0", "0.1-pre-release", true}, // релиз новее пре-релиза с тем же номером
		{"0.1-pre-release", "0.1.0", false},
		{"0.1-pre-release", "0.1-pre-release", false},
		{"v1.9.0", "1.8.5", true},
		{"1.8.0", "1.8.0", false},
		{"1.10.0", "1.9.9", true},
		{"0.1-test.8", "0.1-test.7", true},
		{"0.1-test.7", "0.1-test.8", false},
		{"0.1-test.2", "0.1-test", true},
		{"0.1-test.7", "0.1-test.7", false},
	}
	for _, c := range cases {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, ожидалось %v", c.a, c.b, got, c.want)
		}
	}
}
