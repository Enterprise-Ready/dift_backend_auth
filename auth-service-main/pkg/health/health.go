package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

type Check func(context.Context) error

type Checker struct {
	service string
	version string
	mu      sync.RWMutex
	checks  map[string]Check
}

func New(service, version string) *Checker {
	return &Checker{service: service, version: version, checks: map[string]Check{}}
}
func (c *Checker) Register(name string, fn Check) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks[name] = fn
}
func (c *Checker) LiveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": c.service, "version": c.version})
	}
}
func (c *Checker) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		deps := map[string]string{}
		ok := true
		c.mu.RLock()
		defer c.mu.RUnlock()
		for name, check := range c.checks {
			if err := check(ctx); err != nil {
				deps[name] = err.Error()
				ok = false
			} else {
				deps[name] = "ok"
			}
		}
		status := http.StatusOK
		state := "ready"
		if !ok {
			status = http.StatusServiceUnavailable
			state = "not_ready"
		}
		writeJSON(w, status, map[string]any{"status": state, "service": c.service, "dependencies": deps})
	}
}
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
