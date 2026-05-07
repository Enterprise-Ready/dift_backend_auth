package logger

import (
	"log/slog"
	"os"

	elog "github.com/PlatformCore/libpackage/observability/logging"
)

func New(service string) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{})).With("service", service)
}

func EngineLogger() elog.Logger { return elog.New() }
