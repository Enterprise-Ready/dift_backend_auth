package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"dift_backend_go/auth-service/config"
	inboundhttp "dift_backend_go/auth-service/internal/adapter/inbound/http"
	identityadapter "dift_backend_go/auth-service/internal/adapter/outbound/identity"
	httpinfra "dift_backend_go/auth-service/internal/integration/http"
	authservice "dift_backend_go/auth-service/internal/service"
	"dift_backend_go/auth-service/pkg/logger"
	"dift_backend_go/auth-service/route"
)

func Bootstrap(ctx context.Context, cfg *config.AppConfig) (*App, error) {
	log := logger.New("auth-service")
	slog.SetDefault(log)

	identity := identityadapter.NewLocalIdentityStore()
	authSvc := authservice.NewAuthService(cfg, identity)
	verifySvc := authservice.NewVerificationService()

	authHandler := inboundhttp.NewAuthHandler(authSvc, authSvc)
	verifyHandler := inboundhttp.NewVerificationHandler(verifySvc)
	healthHandler := inboundhttp.NewHealthHandler(identity)

	router := gin.New()
	wireHTTPMiddlewares(router, cfg)
	router.Use(cors.New(cors.Config{AllowOrigins: cfg.Server.CORS.AllowOrigins, AllowMethods: cfg.Server.CORS.AllowMethods, AllowHeaders: cfg.Server.CORS.AllowHeaders}))
	route.RegisterRoutes(router, authHandler, healthHandler, verifyHandler)
	registerOpsRoutes(router)

	srv := httpinfra.NewServer(fmt.Sprintf(":%d", cfg.Server.Port), router, time.Duration(cfg.Server.ReadTimeoutSec)*time.Second, time.Duration(cfg.Server.WriteTimeoutSec)*time.Second, time.Duration(cfg.Server.IdleTimeoutSec)*time.Second)
	_ = ctx
	return &App{Router: router, Server: srv}, nil
}
