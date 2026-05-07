package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"biometric-auth/internal/domain"
	"biometric-auth/internal/service"
)

type contextKey string

const ClaimsKey contextKey = "claims"

// ─── Auth Middleware ──────────────────────────────────────────────────────────

type AuthMiddleware struct {
	tokenSvc *service.TokenService
	auditSvc *service.AuditService
}

func NewAuthMiddleware(tokenSvc *service.TokenService, auditSvc *service.AuditService) *AuthMiddleware {
	return &AuthMiddleware{tokenSvc: tokenSvc, auditSvc: auditSvc}
}

// Authenticate validates the Bearer token and injects claims into context.
func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		if token == "" {
			http.Error(w, `{"error":"missing authorization"}`, http.StatusUnauthorized)
			return
		}

		claims, err := m.tokenSvc.VerifyAccessToken(token)
		if err != nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), ClaimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireStepUp ensures the request has a valid step-up token for sensitive ops.
func (m *AuthMiddleware) RequireStepUp(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(ClaimsKey).(*domain.TokenClaims)
		if !ok {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		if !claims.StepUp {
			http.Error(w, `{"error":"step_up_required","message":"biometric re-authentication required for this action"}`, http.StatusForbidden)
			return
		}

		if claims.StepUpExp != nil && time.Now().After(*claims.StepUpExp) {
			http.Error(w, `{"error":"step_up_expired","message":"step-up session expired, please re-authenticate"}`, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ─── Device Middleware ────────────────────────────────────────────────────────

type DeviceMiddleware struct {
	deviceSvc *service.DeviceService
}

func NewDeviceMiddleware(deviceSvc *service.DeviceService) *DeviceMiddleware {
	return &DeviceMiddleware{deviceSvc: deviceSvc}
}

// ValidateDevice checks the device is active and not revoked for every request.
func (m *DeviceMiddleware) ValidateDevice(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(ClaimsKey).(*domain.TokenClaims)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		device, err := m.deviceSvc.ValidateDevice(claims.DeviceID, claims.UserID)
		if err != nil {
			http.Error(w, `{"error":"device_invalid","message":"device has been revoked or is blocked"}`, http.StatusForbidden)
			return
		}

		// Block rooted devices from accessing sensitive endpoints
		if device.IsRooted || device.IsJailbroken {
			http.Error(w, `{"error":"device_compromised","message":"rooted/jailbroken device detected"}`, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

type rateLimitEntry struct {
	count    int
	windowStart time.Time
}

type RateLimiter struct {
	mu      sync.Mutex
	clients map[string]*rateLimitEntry
	limit   int
	window  time.Duration
}

func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		clients: make(map[string]*rateLimitEntry),
		limit:   100, // 100 req/min per IP
		window:  time.Minute,
	}
	// Cleanup goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			rl.cleanup()
		}
	}()
	return rl
}

func (rl *RateLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)

		rl.mu.Lock()
		entry, exists := rl.clients[ip]
		now := time.Now()

		if !exists || now.Sub(entry.windowStart) > rl.window {
			rl.clients[ip] = &rateLimitEntry{count: 1, windowStart: now}
			rl.mu.Unlock()
		} else {
			entry.count++
			if entry.count > rl.limit {
				rl.mu.Unlock()
				w.Header().Set("Retry-After", "60")
				http.Error(w, `{"error":"rate_limit_exceeded"}`, http.StatusTooManyRequests)
				return
			}
			rl.mu.Unlock()
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for ip, entry := range rl.clients {
		if now.Sub(entry.windowStart) > rl.window*2 {
			delete(rl.clients, ip)
		}
	}
}

// ─── Security Headers ─────────────────────────────────────────────────────────

type SecurityMiddleware struct{}

func NewSecurityMiddleware() *SecurityMiddleware {
	return &SecurityMiddleware{}
}

func (m *SecurityMiddleware) Headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-XSS-Protection", "1; mode=block")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		h.Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		// Remove fingerprinting headers
		h.Del("X-Powered-By")
		h.Del("Server")
		next.ServeHTTP(w, r)
	})
}

// ─── Request Logger ───────────────────────────────────────────────────────────

func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := &responseWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(ww, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.status,
			"duration", time.Since(start),
			"ip", extractIP(r),
		)
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

func extractIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	return r.RemoteAddr
}
