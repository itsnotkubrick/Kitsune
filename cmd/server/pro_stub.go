//go:build !pro

package main

import "github.com/gin-gonic/gin"

// Расширения не подключены.
func registerPro(*gin.RouterGroup) {}
