package metrics

import (
	"net/http"
	"sync"
	"time"

	gometrics "github.com/PlatformCore/libpackage/observability/metrics"
)

var (
	registry = gometrics.NewSimpleRegistry()
	once     sync.Once
)

func initMetrics() {
	once.Do(func() {
		registry.Set("auth_service.info", 1)
	})
}

func RecordLogin(success bool) {
	initMetrics()
	registry.Inc("auth.login.total")
	if success {
		registry.Inc("auth.login.success")
	} else {
		registry.Inc("auth.login.failed")
	}
}
func RecordRegister(success bool) {
	initMetrics()
	registry.Inc("auth.register.total")
	if success {
		registry.Inc("auth.register.success")
	} else {
		registry.Inc("auth.register.failed")
	}
}
func RecordTokenRefresh(success bool) {
	initMetrics()
	registry.Inc("auth.refresh.total")
	if success {
		registry.Inc("auth.refresh.success")
	} else {
		registry.Inc("auth.refresh.failed")
	}
}
func ObserveAuthLatency(start time.Time, operation string) {
	initMetrics()
	registry.Observe("auth."+operation+".latency_ms", float64(time.Since(start).Milliseconds()))
}
func Handler() http.HandlerFunc { initMetrics(); return registry.Handler() }
