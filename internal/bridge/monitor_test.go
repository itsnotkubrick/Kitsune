package bridge

import (
	"errors"
	"testing"
	"time"

	"kitsune/internal/db"
	"kitsune/internal/proto"
)

func TestObserveTransitions(t *testing.T) {
	now := time.Unix(1000, 0)
	id := "mon1"
	if st := StatusOf(id); st.State != "unknown" {
		t.Fatalf("новый узел: %+v", st)
	}
	// две неудачи подряд ещё не падение
	for i := 0; i < 2; i++ {
		if st, changed := Observe(id, true, false, 0, now); st.State == "down" || (changed && st.State == "down") {
			t.Fatalf("после %d неудач узел не должен падать: %+v", i+1, st)
		}
	}
	st, changed := Observe(id, true, false, 0, now)
	if st.State != "down" || !changed || !Down(id) {
		t.Fatalf("три неудачи – узел упал: %+v changed=%v", st, changed)
	}
	// ещё неудача: состояние то же, смены нет
	if _, changed := Observe(id, true, false, 0, now); changed {
		t.Error("повторная неудача не меняет состояние")
	}
	// recovery needs two consecutive successful observations
	st, changed = Observe(id, true, true, 38, now.Add(time.Minute))
	if st.State != "down" || changed {
		t.Fatal("one success must not recover a down node")
	}
	st, changed = Observe(id, true, true, 38, now.Add(2*time.Minute))
	if st.State != "ok" || !changed || st.Ms != 38 || Down(id) {
		t.Fatalf("после ответа: %+v changed=%v", st, changed)
	}
	// одна неудача после ok узел не роняет
	if st, _ := Observe(id, true, false, 0, now.Add(2*time.Minute)); st.State != "ok" {
		t.Errorf("одна неудача после ok: %+v", st)
	}
	// проверить нечем (нет TCP-портов): неизвестно
	if st, _ := Observe("mon2", false, false, 0, now); st.State != "unknown" {
		t.Errorf("без TCP-портов: %+v", st)
	}
}

func TestProbeTCP(t *testing.T) {
	old := dialTCP
	defer func() { dialTCP = old }()
	dialTCP = func(addr string, to time.Duration) (time.Duration, error) {
		if addr == "203.0.113.7:443" {
			return 40 * time.Millisecond, nil
		}
		return 0, errors.New("нет ответа")
	}
	known, ok, ms := ProbeTCP("203.0.113.7", []Forward{{"udp", 443}, {"tcp", 8443}, {"tcp", 443}})
	if !known || !ok || ms != 40 {
		t.Errorf("отвечает один порт: known=%v ok=%v ms=%d", known, ok, ms)
	}
	if known, _, _ := ProbeTCP("203.0.113.7", []Forward{{"udp", 443}}); known {
		t.Error("только UDP: проверить нечем")
	}
	if known, ok, _ := ProbeTCP("203.0.113.7", []Forward{{"tcp", 8443}}); !known || ok {
		t.Error("ни один порт не отвечает")
	}
}

func TestOnlyAndAutoHide(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	nodes, err := Save([]Node{
		{Name: "Узел", Host: "203.0.113.7", Enabled: true, Only: []string{" Reality ", "Reality", ""}, AutoHide: true},
		{Name: "Все", Host: "198.51.100.9", Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes[0].Only) != 1 || nodes[0].Only[0] != "Reality" {
		t.Fatalf("теги очищаются и не повторяются: %v", nodes[0].Only)
	}
	in := []*proto.Profile{prof(proto.VlessReality, "vpn.example.net", "www.example.com"), prof(proto.VlessWS, "vpn.example.net", "")}
	in[0].Name, in[1].Name = "Reality", "WS"
	out := Expand(in)
	// два исходных, у узла «Узел» только Reality, у узла «Все» оба
	if len(out) != 2+1+2 {
		t.Fatalf("ожидали 5 профилей, получили %d", len(out))
	}
	// упавший узел с автоскрытием пропадает из подписки, без автоскрытия остаётся
	for i := 0; i < failsToDown; i++ {
		Observe(nodes[0].ID, true, false, 0, time.Now())
		Observe(nodes[1].ID, true, false, 0, time.Now())
	}
	out = Expand(in)
	if len(out) != 2+2 {
		t.Fatalf("узел с автоскрытием должен пропасть, ждали 4, получили %d", len(out))
	}
	if sel := Select([]db.Inbound{{Tag: "Reality"}, {Tag: "WS"}}, nodes[0].Only); len(sel) != 1 || sel[0].Tag != "Reality" {
		t.Errorf("Select: %v", sel)
	}
}
