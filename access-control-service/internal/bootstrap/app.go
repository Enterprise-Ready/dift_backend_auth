package bootstrap

import (
	"context"
	httpadapter "github.com/diftapp/identity-platform/access-control-service/internal/adapter/http"
	postgresrepo "github.com/diftapp/identity-platform/access-control-service/internal/adapter/repository/postgres"
	app "github.com/diftapp/identity-platform/access-control-service/internal/application/access"
	"github.com/diftapp/identity-platform/access-control-service/internal/config"
	"github.com/diftapp/identity-platform/access-control-service/internal/infra/event"
	pg "github.com/diftapp/identity-platform/access-control-service/internal/infra/postgres"
	"net/http"
)

type App struct {
	cfg    config.Config
	server *http.Server
	events *event.Publisher
}

func NewApp(ctx context.Context) (*App, error) {
	cfg := config.Load()
	db, err := pg.Connect(ctx, cfg.DatabaseDSN)
	if err != nil {
		return nil, err
	}
	events, err := event.NewPublisher(cfg.NATSURL)
	if err != nil {
		return nil, err
	}
	repo := postgresrepo.New(db)
	svc := app.New(repo, events)
	router := httpadapter.NewRouter(svc)
	return &App{cfg: cfg, server: &http.Server{Addr: cfg.HTTPAddr, Handler: router}, events: events}, nil
}
func (a *App) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() { errCh <- a.server.ListenAndServe() }()
	select {
	case <-ctx.Done():
		a.events.Close()
		_ = a.server.Shutdown(context.Background())
		return nil
	case err := <-errCh:
		return err
	}
}
