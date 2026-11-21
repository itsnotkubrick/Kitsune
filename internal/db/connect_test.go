package db

import "testing"

func TestConnectEvents(t *testing.T) {
	t.Chdir(t.TempDir())
	InitDB()
	defer DB.Close()
	u, err := CreateUser("conn", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := GetConnect(u.ID); len(got) != 0 {
		t.Fatalf("новый пользователь: этапы %v", got)
	}
	_ = MarkConnect(u.ID, EvPage, "ios")
	_ = MarkConnect(u.ID, EvPage, "")
	_ = MarkConnect(u.ID, EvSub, "Happ")
	got := GetConnect(u.ID)
	if got[EvPage].Count != 2 || got[EvPage].Extra != "ios" {
		t.Errorf("page: %+v (повтор без пометки не должен её стирать)", got[EvPage])
	}
	if got[EvSub].Extra != "Happ" || got[EvSub].At == 0 {
		t.Errorf("sub: %+v", got[EvSub])
	}
	// пометка из сети чистится: только печатные ASCII, не длиннее 40
	_ = MarkConnect(u.ID, EvAdd, "<script>\n"+string(make([]byte, 0))+"алерт-Мак-очень-длинное-название-приложения-для-проверки-границы")
	if e := GetConnect(u.ID)[EvAdd]; len(e.Extra) > 40 || e.Extra == "" {
		t.Errorf("add: %q", e.Extra)
	}
	if err := DeleteUser(u.ID); err != nil {
		t.Fatal(err)
	}
	if got := GetConnect(u.ID); len(got) != 0 {
		t.Errorf("после удаления пользователя этапы остались: %v", got)
	}
}
