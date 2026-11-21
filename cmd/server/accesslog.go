package main

import (
	"fmt"
	"io"
	"time"

	"github.com/gin-gonic/gin"
)

// Log route templates only. Unmatched paths may contain the panel access key.
func accessLogger(out io.Writer) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		route := c.FullPath()
		if route == "" {
			route = "(unmatched)"
		}
		fmt.Fprintf(out, "[GIN] %s | %3d | %13v | %15s | %-7s %q\n",
			time.Now().Format("2006/01/02 - 15:04:05"), c.Writer.Status(), time.Since(start).Truncate(time.Microsecond),
			c.ClientIP(), c.Request.Method, route)
	}
}
