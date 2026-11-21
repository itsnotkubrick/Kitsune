package proto

import (
	"reflect"
	"testing"
)

func TestWithExtraSNIs(t *testing.T) {
	old := ExtraRealitySNIs
	defer func() { ExtraRealitySNIs = old }()
	base := []string{"www.example.com"}
	if got := withExtraSNIs(base); !reflect.DeepEqual(got, base) {
		t.Errorf("без источника имён список не меняется: %v", got)
	}
	ExtraRealitySNIs = func() []string { return []string{"news.example.com", "www.example.com", ""} }
	got := withExtraSNIs(base)
	if !reflect.DeepEqual(got, []string{"www.example.com", "news.example.com"}) {
		t.Errorf("добавляются только новые непустые имена: %v", got)
	}
	if len(base) != 1 {
		t.Error("исходный список не должен меняться")
	}
}
