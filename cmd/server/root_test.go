package main

import "testing"

func TestNotRoot(t *testing.T) {
	cases := []struct {
		goos string
		euid int
		want bool
	}{
		{"linux", 0, false},
		{"linux", 1000, true},
		{"darwin", 501, false},
		{"windows", -1, false},
	}
	for _, c := range cases {
		if got := notRoot(c.goos, c.euid); got != c.want {
			t.Errorf("%s/%d: получили %v, ждали %v", c.goos, c.euid, got, c.want)
		}
	}
}
