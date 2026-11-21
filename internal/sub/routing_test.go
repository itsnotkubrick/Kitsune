package sub

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"kitsune/internal/db"
	"kitsune/internal/proto"
)

func testProfiles(t *testing.T) []*proto.Profile {
	t.Helper()
	var st proto.Settings
	if err := st.Fill(proto.VlessReality); err != nil {
		t.Fatal(err)
	}
	st.SNI = "vpn.example.com"
	in := db.Inbound{ID: 1, Tag: "R1", Kind: string(proto.VlessReality), Port: 443, Enable: true, Settings: st.JSON()}
	u := db.User{ID: 1, Name: "alice", UUID: "b7d246bd-b6bb-40f7-8f25-7c1eea66d15d", Password: "pw0123456789ab", Enable: true, Vision: true}
	p, err := proto.NewProfile(in, u, proto.Env{Host: "203.0.113.5"})
	if err != nil {
		t.Fatal(err)
	}
	return []*proto.Profile{p}
}

func TestCompileModes(t *testing.T) {
	all := ClientRouting{Mode: "all"}.Compile()
	if all.Enable || all.Final != "PROXY" {
		t.Fatalf("all: %+v", all)
	}
	srv := ClientRouting{Mode: "services", Services: []string{"youtube", "telegram"}}.Compile()
	if !srv.Enable || srv.Final != "DIRECT" || len(srv.Rules) != 3 { // youtube, telegram geosite+geoip
		t.Fatalf("services: %+v", srv)
	}
	ru := ClientRouting{Mode: "local-direct"}.Compile()
	if !ru.Enable || ru.Final != "PROXY" || ru.Rules[0].Action != "DIRECT" {
		t.Fatalf("local-direct: %+v", ru)
	}
}

func TestParseCustom(t *testing.T) {
	rules := ParseCustom("# комментарий\nDOMAIN-SUFFIX,example.com,DIRECT\nbad line\nIP-CIDR,10.0.0.0/8\nUNKNOWN,x,DIRECT\nGEOSITE,netflix,reject")
	if len(rules) != 3 {
		t.Fatalf("ожидалось 3 правила, получено %d: %+v", len(rules), rules)
	}
	if rules[1].Action != "PROXY" || rules[2].Action != "REJECT" {
		t.Fatalf("действия: %+v", rules)
	}
}

func TestRUAppsAndLocalDNS(t *testing.T) {
	rt := ClientRouting{Mode: "local-direct", RUApps: true}.Compile()
	if !rt.RUApps || rt.LocalDNS != DefaultLocalDNS {
		t.Fatalf("настройки не доехали: %+v", rt)
	}
	profiles := testProfiles(t)
	y, err := Clash(profiles, rt)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"PROCESS-NAME,com.vkontakte.android,DIRECT", "nameserver-policy", "geosite:category-ru", "77.88.8.8", "type: fallback", "name: Резерв"} {
		if !strings.Contains(string(y), want) {
			t.Errorf("в Clash нет %q", want)
		}
	}
	j, err := Singbox(profiles, rt)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"package_name"`, "com.vkontakte.android", `"server": "77.88.8.8"`} {
		if !strings.Contains(string(j), want) {
			t.Errorf("в sing-box нет %q", want)
		}
	}
	// без включённой опции приложений в профиле их нет
	off, _ := Clash(profiles, ClientRouting{Mode: "all"}.Compile())
	if strings.Contains(string(off), "PROCESS-NAME") {
		t.Error("приложения не должны попадать без опции")
	}
}

// Проверка настоящим sing-box: SINGBOX_BIN=/путь/к/sing-box go test ./internal/sub -run TestSingboxAccepts
func TestSingboxAcceptsGeneratedConfig(t *testing.T) {
	bin := os.Getenv("SINGBOX_BIN")
	if bin == "" {
		t.Skip("SINGBOX_BIN не задан")
	}
	for _, c := range []ClientRouting{{Mode: "all"}, {Mode: "local-direct", RUApps: true}, {Mode: "services", Services: []string{"youtube"}}} {
		j, err := Singbox(testProfiles(t), c.Compile())
		if err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(t.TempDir(), "c.json")
		if err := os.WriteFile(f, j, 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bin, "check", "-c", f).CombinedOutput(); err != nil {
			t.Fatalf("sing-box отклонил конфиг (%s): %v\n%s", c.Mode, err, out)
		}
	}
}

func TestForClientHidesNaiveFromKaring(t *testing.T) {
	var st proto.Settings
	if err := st.Fill(proto.Naive); err != nil {
		t.Fatal(err)
	}
	in := db.Inbound{ID: 2, Tag: "Naive", Kind: string(proto.Naive), Port: 8445, Enable: true, Settings: st.JSON()}
	u := db.User{ID: 1, Name: "alice", UUID: "b7d246bd-b6bb-40f7-8f25-7c1eea66d15d", Password: "pw0123456789ab", Enable: true}
	naive, err := proto.NewProfile(in, u, proto.Env{Host: "203.0.113.5"})
	if err != nil {
		t.Fatal(err)
	}
	all := append(testProfiles(t), naive)
	if got := ForClient(all, "Karing/1.2.25.2802 ios"); len(got) != 1 || got[0].Kind == proto.Naive {
		t.Fatalf("Karing не должен получать Naive: %d профилей", len(got))
	}
	if got := ForClient(all, "sing-box/1.14"); len(got) != 2 {
		t.Fatal("другим клиентам Naive остаётся")
	}
}
