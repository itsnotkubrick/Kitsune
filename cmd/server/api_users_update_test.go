package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
)

// Если ядро не приняло конфиг (например, ещё не установлено), правка пользователя уже записана в базу:
// ответ не должен быть ошибкой, иначе интерфейс покажет «не сохранено» и не обновит список.
func TestUpdateUserSavedWhenCoreRejects(t *testing.T) {
	t.Chdir(t.TempDir())
	db.InitDB()
	defer db.DB.Close()
	u, err := db.CreateUser("upd", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.PUT("/users/:id", handleUpdateUser)
	req := httptest.NewRequest(http.MethodPut, "/users/"+itoa(u.ID), strings.NewReader(`{"note":"saved","ip_limit":3}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	got, _ := db.GetUser(u.ID)
	if got.Note != "saved" || got.IPLimit != 3 {
		t.Errorf("изменения не записаны: %+v", got)
	}
}
