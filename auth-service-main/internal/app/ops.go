package app

import (
	"dift_backend_go/auth-service/pkg/metrics"
	"net/http"
)

func metricsHandler() http.HandlerFunc { return metrics.Handler() }
