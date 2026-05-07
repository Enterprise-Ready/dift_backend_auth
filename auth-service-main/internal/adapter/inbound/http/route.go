package http

import "github.com/gin-gonic/gin"

type Handlers struct {
	Auth   *AuthHandler
	Health *HealthHandler
}

func RegisterRoutes(router *gin.Engine, h Handlers) {
	router.GET("/health", h.Health.Health)
	router.GET("/ready", h.Health.Ready)

	api := router.Group("/api/v1/auth")
	{
		api.POST("/login/email", h.Auth.LoginEmail)
		api.POST("/register/email", h.Auth.RegisterEmail)
	}
}
