package config

import "os"

type Config struct {
	HTTPAddr    string
	DatabaseDSN string
	NATSURL     string
}

func Load() Config {
	return Config{
		HTTPAddr:    env("HTTP_ADDR", ":8080"),
		DatabaseDSN: env("DATABASE_DSN", "postgres://platform:platform@localhost:5432/identity_platform?sslmode=disable"),
		NATSURL:     env("NATS_URL", "nats://localhost:4222"),
	}
}

func env(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
