package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dift_backend_go/auth-service/config"
	"dift_backend_go/auth-service/internal/app"
)

func main() {
	cfg, err := config.Load("config/config.yaml")
	if err != nil {
		log.Fatalf("load config failed: %v", err)
	}

	application, err := app.Bootstrap(context.Background(), cfg)
	if err != nil {
		log.Fatalf("bootstrap failed: %v", err)
	}

	go func() {
		if err := application.Start(); err != nil {
			log.Printf("auth-service stopped: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Server.ShutdownSec)*time.Second)
	defer cancel()
	if err := application.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}
