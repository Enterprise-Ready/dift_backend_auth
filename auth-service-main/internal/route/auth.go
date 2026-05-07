package route

import (
	adapterhttp "dift_backend_go/auth-service/internal/adapter/inbound/http"

	"github.com/gin-gonic/gin"
)

func RegisterAuthRoutes(r *gin.Engine, auth *adapterhttp.AuthHandler, health *adapterhttp.HealthHandler, verify *adapterhttp.VerificationHandler) {
	r.GET("/health", health.Health)
	r.GET("/ready", health.Ready)

	api := r.Group("/api/v1/auth")
	{
		api.POST("/register/email", auth.RegisterEmail)
		api.POST("/login/email", auth.LoginEmail)
		api.POST("/refresh", auth.RefreshToken)
		api.POST("/logout", auth.Logout)
	}

	me := r.Group("/api/v1")
	me.Use(adapterhttp.AuthBearerMiddleware())
	{
		me.GET("/me", auth.Me)
	}

	verification := r.Group("/api/v1")
	{
		verification.POST("/otp/challenges", verify.CreateOTP)
		verification.POST("/otp/verify", verify.VerifyOTP)
		verification.POST("/face/verify", verify.VerifyFace)
		verification.POST("/risk/evaluate", verify.EvaluateRisk)
		verification.GET("/audit/events", verify.ListAudit)
	}
}
