package app

import (
	"dift_backend_go/auth-service/config"
	inboundhttp "dift_backend_go/auth-service/internal/adapter/inbound/http"
	"github.com/gin-gonic/gin"
	"time"
)

func wireHTTPMiddlewares(r *gin.Engine, cfg *config.AppConfig) {
	_ = cfg
	r.Use(inboundhttp.RequestIDMiddleware())
	r.Use(inboundhttp.RecoveryMiddleware())
	r.Use(inboundhttp.SecurityHeadersMiddleware())
	r.Use(inboundhttp.BodyLimitMiddleware(1 << 20))
	r.Use(inboundhttp.IdempotencyMiddleware(10 * time.Minute))
	r.Use(inboundhttp.AuditMiddleware())
	r.Use(inboundhttp.RateLimitMiddleware())
	r.Use(inboundhttp.AccessLogMiddleware())
}
