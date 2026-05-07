package app

import (
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

type App struct {
	Router *gin.Engine
	Server interface {
		Start() error
		Shutdown(context.Context) error
	}
}

func (a *App) Start() error {
	if a.Server == nil {
		return errors.New("http server is nil")
	}
	log.Printf("auth-service started")
	return a.Server.Start()
}
func (a *App) Shutdown(ctx context.Context) error {
	if a.Server != nil {
		return a.Server.Shutdown(ctx)
	}
	return nil
}

func registerOpsRoutes(r *gin.Engine) {
	r.GET("/health/live", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "auth-service"}) })
	r.GET("/metrics/business", gin.WrapF(metricsHandler()))
}
