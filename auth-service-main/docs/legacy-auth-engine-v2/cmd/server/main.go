//go:build legacy
// +build legacy

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/enterprise/auth-engine/internal/audit"
	"github.com/enterprise/auth-engine/internal/auth"
	authhandler "github.com/enterprise/auth-engine/internal/auth"
	"github.com/enterprise/auth-engine/internal/config"
	"github.com/enterprise/auth-engine/internal/face"
	"github.com/enterprise/auth-engine/internal/middleware"
	"github.com/enterprise/auth-engine/internal/oauth"
	"github.com/enterprise/auth-engine/internal/otp"
	"github.com/enterprise/auth-engine/internal/providers"
	jwtpkg "github.com/enterprise/auth-engine/pkg/jwt"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func main() {
	// ── Config ────────────────────────────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		panic(fmt.Sprintf("load config: %v", err))
	}

	// ── Logger ────────────────────────────────────────────────────────────────
	var log *zap.Logger
	if cfg.Server.Mode == "debug" {
		log, _ = zap.NewDevelopment()
	} else {
		log, _ = zap.NewProduction()
	}
	defer log.Sync()

	// ── Database ──────────────────────────────────────────────────────────────
	db, err := gorm.Open(postgres.Open(cfg.Database.DSN), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Warn),
	})
	if err != nil {
		log.Fatal("connect database", zap.Error(err))
	}

	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(cfg.Database.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.Database.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.Database.ConnMaxLifetime)

	// Run migrations
	if err := runMigrations(db); err != nil {
		log.Fatal("run migrations", zap.Error(err))
	}

	// ── Redis ─────────────────────────────────────────────────────────────────
	rdb := redis.NewClient(&redis.Options{
		Addr:         cfg.Redis.Addr,
		Password:     cfg.Redis.Password,
		DB:           cfg.Redis.DB,
		PoolSize:     cfg.Redis.PoolSize,
		MaxRetries:   cfg.Redis.MaxRetries,
		DialTimeout:  cfg.Redis.DialTimeout,
		ReadTimeout:  cfg.Redis.ReadTimeout,
		WriteTimeout: cfg.Redis.WriteTimeout,
	})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		log.Fatal("connect redis", zap.Error(err))
	}

	// ── Repositories ──────────────────────────────────────────────────────────
	// In production: inject concrete GORM/Redis implementations
	// userRepo   := repository.NewUserRepository(db)
	// sessionRepo := repository.NewSessionRepository(db, rdb)
	// otpStore    := repository.NewOTPStore(rdb)
	// auditRepo   := repository.NewAuditRepository(db)
	// oauthRepo   := repository.NewOAuthRepository(db)
	// faceStore   := repository.NewFaceStore(db)

	// ── Email / SMS Providers ─────────────────────────────────────────────────
	emailProvider, err := providers.NewEmailProvider(&cfg.Email)
	if err != nil {
		log.Warn("email provider init", zap.Error(err))
	}
	emailNotifier := providers.NewEmailNotifier(emailProvider, &cfg.Email)

	smsProvider, err := providers.NewSMSProvider(&cfg.SMS)
	if err != nil {
		log.Warn("sms provider init", zap.Error(err))
	}
	smsNotifier := providers.NewSMSNotifier(smsProvider)

	// Composite notifier
	type compositeNotifier struct {
		*providers.EmailNotifier
		*providers.SMSNotifier
	}
	notifier := &compositeNotifier{emailNotifier, smsNotifier}

	// ── External Providers (Firebase / Supabase) ───────────────────────────────
	_ = providers.NewExternalProviders(context.Background(), cfg)

	// ── Services ──────────────────────────────────────────────────────────────
	jwtMgr := jwtpkg.NewManager(
		cfg.JWT.AccessSecret,
		cfg.JWT.RefreshSecret,
		cfg.JWT.AccessExpiry,
		cfg.JWT.RefreshExpiry,
		cfg.JWT.Issuer,
	)

	// OTP service (inject real stores in production)
	otpSvc := otp.NewService(&cfg.OTP, nil /* otpStore */, notifier, log)

	// Face service (inject real store in production)
	faceSvc := face.NewService(&cfg.Face, nil /* faceStore */, log)

	// OAuth registry
	oauthReg := oauth.NewRegistry(&cfg.OAuth)

	// Audit service (inject real repo in production)
	_ = audit.NewService(nil /* auditRepo */, &cfg.Audit, log)

	// Auth service (inject real repos in production)
	authSvc := auth.NewService(
		cfg,
		nil, // userRepo
		nil, // sessionRepo
		nil, // oauthRepo
		nil, // auditRepo (wrapped as auth.AuditRepository)
		otpSvc,
		faceSvc,
		oauthReg,
		jwtMgr,
		log,
	)

	// ── Middleware ────────────────────────────────────────────────────────────
	rateLimiter := middleware.NewRateLimiter(rdb, log)

	// ── Router ────────────────────────────────────────────────────────────────
	gin.SetMode(cfg.Server.Mode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.RequestID())
	r.Use(middleware.Logger(log))
	r.Use(middleware.SecurityHeaders())

	// CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Request-ID"},
		ExposeHeaders:    []string{"X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// IP Whitelist (admin routes)
	// adminWhitelist := middleware.IPWhitelist(cfg.Security.IPWhitelist)

	// Health
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "time": time.Now().UTC()})
	})

	// Auth routes
	jwtMiddleware := middleware.JWTAuth(jwtMgr)
	authHandler := authhandler.NewHandler(authSvc, log)
	apiV1 := r.Group("/api/v1")
	authGroup := apiV1.Group("/auth")
	authHandler.RegisterRoutes(authGroup, rateLimiter, jwtMiddleware)

	// Metrics endpoint (Prometheus)
	// r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// ── Server ────────────────────────────────────────────────────────────────
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)

	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	go func() {
		log.Info("starting server", zap.String("addr", addr))
		var err error
		if cfg.Server.TLSEnabled {
			err = srv.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatal("server error", zap.Error(err))
		}
	}()

	// ── Graceful Shutdown ─────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error("server shutdown error", zap.Error(err))
	}
	log.Info("server stopped")
}

func runMigrations(db *gorm.DB) error {
	// In production: use golang-migrate or GORM AutoMigrate
	// db.AutoMigrate(
	//   &models.User{},
	//   &models.Session{},
	//   &models.OTP{},
	//   &models.OAuthProvider{},
	//   &models.FaceEnrollment{},
	//   &models.AuditLog{},
	//   &models.APIKey{},
	// )
	return nil
}
