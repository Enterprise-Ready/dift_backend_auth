package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"biometric-auth/internal/config"
	"biometric-auth/internal/handler"
	"biometric-auth/internal/middleware"
	"biometric-auth/internal/repository"
	"biometric-auth/internal/service"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	cfg := config.Load()

	// Init repositories (in-memory for demo; swap with DB in prod)
	userRepo := repository.NewUserRepository()
	deviceRepo := repository.NewDeviceRepository()
	sessionRepo := repository.NewSessionRepository()
	auditRepo := repository.NewAuditRepository()
	challengeRepo := repository.NewChallengeRepository()

	// Init services
	cryptoSvc := service.NewCryptoService(cfg)
	tokenSvc := service.NewTokenService(cfg, sessionRepo)
	auditSvc := service.NewAuditService(auditRepo)
	deviceSvc := service.NewDeviceService(deviceRepo, auditSvc, cryptoSvc)
	biometricSvc := service.NewBiometricService(cfg, cryptoSvc, deviceSvc, challengeRepo, auditSvc)
	authSvc := service.NewAuthService(cfg, userRepo, tokenSvc, deviceSvc, biometricSvc, auditSvc)

	// Init handlers
	authHandler := handler.NewAuthHandler(authSvc, auditSvc)
	biometricHandler := handler.NewBiometricHandler(biometricSvc, authSvc, auditSvc)
	deviceHandler := handler.NewDeviceHandler(deviceSvc, auditSvc)
	auditHandler := handler.NewAuditHandler(auditSvc)

	// Middlewares
	authMW := middleware.NewAuthMiddleware(tokenSvc, auditSvc)
	deviceMW := middleware.NewDeviceMiddleware(deviceSvc)
	rateLimiter := middleware.NewRateLimiter()
	securityMW := middleware.NewSecurityMiddleware()

	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(securityMW.Headers)
	r.Use(rateLimiter.Limit)
	r.Use(middleware.RequestLogger)

	// Public routes
	r.Group(func(r chi.Router) {
		r.Post("/auth/login", authHandler.Login)
		r.Post("/auth/otp/send", authHandler.SendOTP)
		r.Post("/auth/otp/verify", authHandler.VerifyOTP)
		r.Post("/auth/token/refresh", authHandler.RefreshToken)
	})

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(authMW.Authenticate)
		r.Use(deviceMW.ValidateDevice)

		// Biometric enrollment & auth
		r.Post("/biometric/challenge", biometricHandler.GetChallenge)
		r.Post("/biometric/enroll", biometricHandler.Enroll)
		r.Post("/biometric/authenticate", biometricHandler.Authenticate)
		r.Delete("/biometric/unenroll", biometricHandler.Unenroll)

		// Device management
		r.Get("/devices", deviceHandler.ListDevices)
		r.Delete("/devices/{deviceID}", deviceHandler.RevokeDevice)
		r.Post("/devices/verify", deviceHandler.VerifyDevice)

		// Auth management
		r.Post("/auth/logout", authHandler.Logout)
		r.Post("/auth/logout/all", authHandler.LogoutAll)

		// Step-up auth for payment (requires fresh biometric)
		r.Group(func(r chi.Router) {
			r.Use(authMW.RequireStepUp)
			r.Post("/payment/authorize", authHandler.AuthorizePayment)
		})

		// Audit logs (admin)
		r.Get("/audit/logs", auditHandler.GetLogs)
	})

	srv := &http.Server{
		Addr:         cfg.ServerAddr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("server starting", "addr", cfg.ServerAddr)
		if err := srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != nil && err != http.ErrServerClosed {
			slog.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("graceful shutdown failed", "error", err)
	}
	slog.Info("server stopped")
}
