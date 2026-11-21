package sub

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"kitsune/internal/db"
	"kitsune/internal/proto"
)

func twoProfiles(t *testing.T) []*proto.Profile {
	t.Helper()
	ps := testProfiles(t)
	var st proto.Settings
	if err := st.Fill(proto.VlessXHTTP); err != nil {
		t.Fatal(err)
	}
	st.SNI = "vpn.example.com"
	in := db.Inbound{ID: 2, Tag: "X1", Kind: string(proto.VlessXHTTP), Port: 8443, Enable: true, Settings: st.JSON()}
	p, err := proto.NewProfile(in, ps[0].U, proto.Env{Host: "203.0.113.5"})
	if err != nil {
		t.Fatal(err)
	}
	return append(ps, p)
}

func TestXrayJSONShape(t *testing.T) {
	raw, err := XrayJSON(twoProfiles(t))
	if err != nil {
		t.Fatal(err)
	}
	var cfgs []map[string]any
	if err := json.Unmarshal(raw, &cfgs); err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 3 { // Авто + два подключения
		t.Fatalf("конфигов %d, ждали 3", len(cfgs))
	}
	if cfgs[0]["remarks"] != "Kitsune: Авто" || cfgs[0]["burstObservatory"] == nil {
		t.Fatalf("первый конфиг должен быть «Авто» с проверкой: %v", cfgs[0]["remarks"])
	}
	if cfgs[1]["burstObservatory"] != nil {
		t.Error("у одиночного конфига проверки быть не должно")
	}
	// один подходящий тип – автовыбор не нужен
	one, _ := XrayJSON(testProfiles(t))
	var c1 []map[string]any
	_ = json.Unmarshal(one, &c1)
	if len(c1) != 1 || strings.Contains(string(one), "balancers") {
		t.Errorf("при одном подключении ждали один конфиг без балансировщика, получили %d", len(c1))
	}
}

func TestDetectXray(t *testing.T) {
	if DetectFormat("xray", "x") != FormatXray || DetectFormat("", "INCY/1.2") != FormatXray {
		t.Error("xray не определяется")
	}
	if DetectFormat("", "Happ/2.0") != FormatRaw {
		t.Error("Happ остаётся на обычной подписке, пока формат не проверен на живом приложении")
	}
}

// С настоящим Xray: каждый конфиг массива должен пройти проверку ядра.
func TestXrayAcceptsGeneratedConfigs(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("XRAY_BIN не задан")
	}
	raw, err := XrayJSON(twoProfiles(t))
	if err != nil {
		t.Fatal(err)
	}
	var cfgs []json.RawMessage
	_ = json.Unmarshal(raw, &cfgs)
	for i, c := range cfgs {
		f := filepath.Join(t.TempDir(), "c.json")
		if err := os.WriteFile(f, c, 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bin, "run", "-test", "-c", f).CombinedOutput(); err != nil {
			t.Fatalf("Xray отклонил конфиг %d: %v\n%s", i, err, out)
		}
	}
}

func TestUDPFirstOrder(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	add := func(tag string, k proto.Kind, port int) {
		var st proto.Settings
		if err := st.Fill(k); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.Exec(`INSERT INTO inbounds (tag, protocol, port, enable, sni, kind, settings) VALUES (?, 'x', ?, 1, '', ?, ?)`, tag, port, string(k), st.JSON()); err != nil {
			t.Fatal(err)
		}
	}
	add("R", proto.VlessReality, 443)
	add("H", proto.Hysteria2, 8444)
	u, err := db.CreateUser("anna", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	env := proto.Env{Host: "203.0.113.5"}
	before := Profiles(*u, env)
	if len(before) < 2 || before[0].Kind != proto.VlessReality {
		t.Fatalf("порядок по умолчанию: %v", len(before))
	}
	_ = db.SetSetting("sub_udp_first", "1")
	after := Profiles(*u, env)
	if after[0].Kind != proto.Hysteria2 {
		t.Fatalf("UDP должен идти первым, первым стоит %s", after[0].Kind)
	}
}
