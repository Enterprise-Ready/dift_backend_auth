package main

import (
	"context"
	"github.com/diftapp/identity-platform/access-control-service/internal/bootstrap"
	"log"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	app, err := bootstrap.NewApp(ctx)
	if err != nil {
		log.Fatal(err)
	}
	if err := app.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
