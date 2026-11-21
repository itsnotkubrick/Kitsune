package main

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
	"kitsune/internal/stub"
)

func TestStubRandomRollsBackOnApplyError(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	_ = db.SetSetting("stub_site", "blog")

	if _, err := stubRandomWith(func() error { return errors.New("boom") }); err == nil {
		t.Fatal("ошибка применения должна дойти до клиента")
	}
	if got := db.GetSetting("stub_site", ""); got != "blog" {
		t.Fatalf("после ошибки должна остаться прежняя заглушка, а не %q", got)
	}

	id, err := stubRandomWith(func() error { return nil })
	if err != nil || id == "blog" || !stub.Exists(id) || db.GetSetting("stub_site", "") != id {
		t.Fatalf("успешная смена: id=%q err=%v", id, err)
	}
}

func TestStubSetRollsBackOnApplyError(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	_ = db.SetSetting("stub_site", "blog")

	if err := stubSetWith("docs", func() error { return errors.New("boom") }); err == nil {
		t.Fatal("ошибка применения должна дойти до клиента")
	}
	if got := db.GetSetting("stub_site", ""); got != "blog" {
		t.Fatalf("после ошибки должна остаться прежняя заглушка, а не %q", got)
	}
	if err := stubSetWith("docs", func() error { return nil }); err != nil || db.GetSetting("stub_site", "") != "docs" {
		t.Fatalf("успешная смена: err=%v", err)
	}
}

func TestStubCustomDeleteGivesRandomPage(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	initStub()
	_ = db.SetSetting("stub_custom_html", "<html>mine</html>")
	stub.SetCustom("<html>mine</html>")
	_ = db.SetSetting("stub_site", stub.CustomID)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("DELETE", "/", nil)
	handleStubCustomDelete(c)
	if got := db.GetSetting("stub_site", ""); !stub.Exists(got) || got == stub.CustomID || stub.Custom() != "" {
		t.Fatalf("после удаления своей страницы нужна случайная заглушка, а не %q", got)
	}
}

// Ошибка чтения базы при старте не должна затирать сохранённый выбор заглушки.
func TestInitStubKeepsSettingsOnReadError(t *testing.T) {
	t.Chdir(t.TempDir())
	stubReadRetry = 0
	db.InitDB()
	initStub()
	_ = db.SetSetting("stub_site", "status")

	_ = db.DB.Close() // чтение и запись теперь падают
	initStub()
	db.InitDB()
	if db.GetSetting("stub_site", "") != "status" {
		t.Fatal("при ошибке чтения выбор заглушки был перезаписан")
	}
}

// При первом запуске и при мусоре в настройке выбирается существующая заглушка.
func TestInitStubPicksValidPage(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	initStub()
	first := db.GetSetting("stub_site", "")
	if !stub.Exists(first) || first == stub.CustomID {
		t.Fatalf("первая настройка: %q", first)
	}
	initStub()
	if db.GetSetting("stub_site", "") != first {
		t.Fatal("после перезапуска выбор изменился")
	}
	_ = db.SetSetting("stub_site", "мусор")
	initStub()
	if got := db.GetSetting("stub_site", ""); !stub.Exists(got) || got == "мусор" {
		t.Fatalf("мусор в настройке: %q", got)
	}
}
