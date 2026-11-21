package main

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"kitsune/internal/check"
	"kitsune/internal/db"
	"kitsune/internal/proto"
)

func TestPickSNI(t *testing.T) {
	list := []string{"a.example", "b.example", "c.example"}
	ok := func(s string) bool { return s != "b.example" }
	if got := pickSNI(list, "a.example", ok); got != "c.example" {
		t.Errorf("текущий и негодный пропускаются: %q", got)
	}
	if got := pickSNI(list, "", func(string) bool { return false }); got != "" {
		t.Errorf("если ничего не подошло, пусто: %q", got)
	}
}

func TestFixPanelPath(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	_ = db.SetSetting("panel_path", "") // новая база сама создаёт путь: проверяем случай без него
	msg, err := check.Apply("panelpath", func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	p := db.GetSetting("panel_path", "")
	if !regexp.MustCompile(`^[a-z0-9]{10}$`).MatchString(p) || !strings.Contains(msg, "/"+p+"/") {
		t.Fatalf("путь %q, сообщение %q", p, msg)
	}
	// повторно путь не меняется: иначе ссылка на панель потерялась бы
	if _, err := check.Apply("panelpath", func() error { return nil }); err != nil || db.GetSetting("panel_path", "") != p {
		t.Error("существующий путь не должен меняться")
	}
	if _, err := check.Apply("sni:abc", func() error { return nil }); err == nil {
		t.Error("неверный аргумент должен давать ошибку")
	}
	if _, err := check.Apply("nope", func() error { return nil }); err == nil {
		t.Error("неизвестное исправление должно давать ошибку")
	}
}

func TestFixCerts(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	old := acmeFiles
	defer func() { acmeFiles = old }()
	acmeFiles = func(d string) (string, string, bool, error) { return "c.pem", "k.pem", false, nil }

	if _, err := fixCerts(""); err == nil {
		t.Fatal("без Let's Encrypt у панели исправление не должно работать")
	}
	_ = db.SetSetting("panel_tls", `{"mode":"acme","port":9443,"domain":"Panel.Example.com","redirect":true}`)
	var st proto.Settings
	if err := st.Fill(proto.VlessWS); err != nil {
		t.Fatal(err)
	}
	_, err := db.DB.Exec(`INSERT INTO inbounds (tag, protocol, port, enable, sni, kind, settings) VALUES ('WS', 'vless', 8444, 1, '', ?, ?)`, string(proto.VlessWS), st.JSON())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fixCerts("") // ядра в тесте нет: ошибка применения допустима, настройки уже записаны
	inbounds, _ := db.GetInbounds()
	got := proto.ParseSettings(inbounds[0].Settings)
	if got.CertMode != "acme" || got.SNI != "panel.example.com" || inbounds[0].SNI != "panel.example.com" {
		t.Fatalf("подключение не переведено: %+v", got)
	}
	// сертификат не получен: ничего не меняется
	_, _ = db.DB.Exec(`UPDATE inbounds SET settings = ?, sni = '' WHERE id = ?`, st.JSON(), inbounds[0].ID)
	acmeFiles = func(string) (string, string, bool, error) {
		return "", "", false, errors.New("нет сертификата")
	}
	if _, err := fixCerts(""); err == nil {
		t.Fatal("при ошибке сертификата должна быть ошибка")
	}
	again, _ := db.GetInbounds()
	if proto.ParseSettings(again[0].Settings).CertMode == "acme" {
		t.Fatal("при ошибке сертификата подключения менять нельзя")
	}
}
