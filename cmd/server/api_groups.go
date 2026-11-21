package main

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
)

func handleGroupsGet(c *gin.Context) {
	gs, _ := db.GetGroups()
	ts, _ := db.GetTemplates()
	c.JSON(http.StatusOK, gin.H{"groups": gs, "templates": ts})
}

func handleGroupSave(c *gin.Context) {
	var g db.Group
	if err := c.ShouldBindJSON(&g); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}
	if id, err := strconv.Atoi(c.Param("id")); err == nil {
		g.ID = id
	}
	id, err := db.SaveGroup(g)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_ = applyCores() // доступ пользователей к подключениям мог измениться
	c.JSON(http.StatusOK, gin.H{"message": "Группа сохранена", "id": id})
}

func handleGroupDelete(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := db.DeleteGroup(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_ = applyCores()
	c.JSON(http.StatusOK, gin.H{"message": "Группа удалена"})
}

func handleTemplateSave(c *gin.Context) {
	var t db.Template
	if err := c.ShouldBindJSON(&t); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}
	if id, err := strconv.Atoi(c.Param("id")); err == nil {
		t.ID = id
	}
	id, err := db.SaveTemplate(t)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Шаблон сохранён", "id": id})
}

func handleTemplateDelete(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := db.DeleteTemplate(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Шаблон удалён"})
}
