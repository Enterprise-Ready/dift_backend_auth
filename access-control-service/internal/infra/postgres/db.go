package postgres

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
)

func Connect(ctx context.Context, dsn string) (*pgxpool.Pool, error) { return pgxpool.New(ctx, dsn) }
