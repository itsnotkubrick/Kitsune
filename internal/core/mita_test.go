package core

import (
	"encoding/json"
	"testing"

	"kitsune/internal/db"
	"kitsune/internal/proto"
)

func TestBuildMitaConfigFollowsDocs(t *testing.T) {
	s := proto.Settings{Transport: "UDP", MTU: "1300", PortRange: "2012-2022"}
	ib := db.Inbound{ID: 1, Tag: "Mieru", Kind: string(proto.Mieru), Port: 8446, Settings: s.JSON()}
	users := []db.User{
		{Name: "alice", Password: "pw1", Enable: true},
		{Name: "bob", Password: "pw2", Enable: false}, // отключённых в конфиге нет
	}
	cfg := BuildMitaConfig(ib, users)
	raw, _ := json.Marshal(cfg)
	var got struct {
		PortBindings []map[string]any `json:"portBindings"`
		Users        []map[string]any `json:"users"`
		MTU          int              `json:"mtu"`
		Logging      string           `json:"loggingLevel"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.PortBindings) != 1 || got.PortBindings[0]["portRange"] != "2012-2022" || got.PortBindings[0]["protocol"] != "UDP" {
		t.Fatalf("portBindings: %v", got.PortBindings)
	}
	if _, has := got.PortBindings[0]["port"]; has {
		t.Fatal("при диапазоне портов поле port не нужно")
	}
	if len(got.Users) != 1 || got.Users[0]["name"] != "alice" || got.Users[0]["password"] != "pw1" {
		t.Fatalf("users: %v", got.Users)
	}
	if got.MTU != 1300 || got.Logging != "INFO" {
		t.Fatalf("mtu/logging: %d %s", got.MTU, got.Logging)
	}
}

func TestMTGConfig(t *testing.T) {
	s := proto.Settings{}
	if err := s.Fill(proto.MTProto); err != nil {
		t.Fatal(err)
	}
	ib := db.Inbound{ID: 7, Kind: string(proto.MTProto), Port: 8447, Settings: s.JSON()}
	cfg := mtgConfig(ib, s)
	for _, want := range []string{`secret = "ee`, `bind-to = "0.0.0.0:8447"`, "concurrency = 8192", "[stats.prometheus]\nenabled = false"} {
		if !contains(cfg, want) {
			t.Fatalf("в конфиге mtg нет %q:\n%s", want, cfg)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestBuildTelemtConfigPerUserSecretsAndLimits(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB() // соль установки создаётся при инициализации базы
	s := proto.Settings{Engine: "telemt"}
	if err := s.Fill(proto.MTProto); err != nil {
		t.Fatal(err)
	}
	ib := db.Inbound{ID: 3, Tag: "MT", Kind: string(proto.MTProto), Port: 8447, Settings: s.JSON()}
	users := []db.User{
		{ID: 1, Name: "alice", UUID: "uuid-alice", Enable: true, TrafficLimit: 10_000, UsedTraffic: 4_000, ExpiryTime: 4102444800000, IPLimit: 2},
		{ID: 2, Name: "bob", UUID: "uuid-bob", Enable: true},
		{ID: 3, Name: "off", UUID: "uuid-off", Enable: false},
	}
	cfg := BuildTelemtConfig(ib, users, proto.Env{Host: "203.0.113.5"}, "/tmp/t")
	secretA, secretB := proto.MTProtoUserSecret(db.MTProtoSalt(), "uuid-alice"), proto.MTProtoUserSecret(db.MTProtoSalt(), "uuid-bob")
	if secretA == secretB || len(secretA) != 32 {
		t.Fatalf("секреты: %s %s", secretA, secretB)
	}
	for _, want := range []string{"port = 8447", `tls_domain = "www.cloudflare.com"`, `"alice" = "` + secretA + `"`, `"bob" = "` + secretB + `"`,
		"[access.user_data_quota]\n\"alice\" = 6000", `"alice" = "2100-01-01T00:00:00Z"`, "[access.user_max_unique_ips]\n\"alice\" = 2", `public_host = "203.0.113.5"`, "enabled = false"} {
		if !contains(cfg, want) {
			t.Fatalf("в конфиге telemt нет %q:\n%s", want, cfg)
		}
	}
	if contains(cfg, `"off"`) || contains(cfg, `"bob" = 0`) {
		t.Fatalf("отключённого и пользователей без лимитов в секциях лимитов быть не должно:\n%s", cfg)
	}
	routed := BuildTelemtConfig(ib, users, proto.Env{Host: "h", Single: true}, "/tmp/t")
	if !contains(routed, `ip = "127.0.0.1"`) || !contains(routed, "public_port = 443") {
		t.Fatalf("в режиме «всё на 443»: слушать локально, в ссылках порт 443:\n%s", routed)
	}
}

// Живой сервер: mita 3.38.1 падает на dns.dualStack = "PREFER_IPV4", поэтому блока dns в конфиге быть не должно.
func TestMitaConfigHasNoDNSBlock(t *testing.T) {
	cfg := BuildMitaConfig(db.Inbound{ID: 1, Kind: string(proto.Mieru), Port: 8446, Settings: "{}"}, nil)
	if _, has := cfg["dns"]; has {
		t.Fatal("в конфиге mita не должно быть блока dns")
	}
}
