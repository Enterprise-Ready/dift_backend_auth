//go:build legacy
// +build legacy

package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/enterprise/auth-engine/internal/config"
	jwtpkg "github.com/enterprise/auth-engine/pkg/jwt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	CtxUserID    = "user_id"
	CtxSessionID = "session_id"
	CtxRole      = "role"
	CtxClaims    = "claims"
)

// ─── JWT Auth ─────────────────────────────────────────────────────────────────

func JWTAuth(jwtMgr *jwtpkg.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}

		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization format"})
			return
		}

		claims, err := jwtMgr.ParseAccessToken(parts[1])
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		c.Set(CtxUserID, claims.UserID)
		c.Set(CtxSessionID, claims.SessionID)
		c.Set(CtxRole, claims.Role)
		c.Set(CtxClaims, claims)
		c.Next()
	}
}

func RequireMFA() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := c.MustGet(CtxClaims).(*jwtpkg.Claims)
		if !ok || !claims.MFADone {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "mfa required"})
			return
		}
		c.Next()
	}
}

func RequireRole(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(c *gin.Context) {
		role, _ := c.Get(CtxRole)
		if !allowed[fmt.Sprint(role)] {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}
		c.Next()
	}
}

func GetUserID(c *gin.Context) (uuid.UUID, bool) {
	v, exists := c.Get(CtxUserID)
	if !exists {
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok
}

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

type RateLimiter struct {
	rdb    *redis.Client
	log    *zap.Logger
}

func NewRateLimiter(rdb *redis.Client, log *zap.Logger) *RateLimiter {
	return &RateLimiter{rdb: rdb, log: log}
}

// Sliding window rate limiter using Redis
func (rl *RateLimiter) Limit(key string, limit int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		rkey := fmt.Sprintf("rl:%s:%s", key, ip)
		ctx := context.Background()

		pipe := rl.rdb.Pipeline()
		now := time.Now().UnixMilli()
		windowMs := window.Milliseconds()

		pipe.ZRemRangeByScore(ctx, rkey, "0", fmt.Sprintf("%d", now-windowMs))
		pipe.ZAdd(ctx, rkey, redis.Z{Score: float64(now), Member: fmt.Sprintf("%d", now)})
		pipe.ZCard(ctx, rkey)
		pipe.Expire(ctx, rkey, window)

		results, err := pipe.Exec(ctx)
		if err != nil {
			rl.log.Error("rate limiter redis error", zap.Error(err))
			c.Next()
			return
		}

		count := results[2].(*redis.IntCmd).Val()
		remaining := int64(limit) - count

		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", max(0, remaining)))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(window).Unix()))

		if count > int64(limit) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "rate limit exceeded",
				"retry_after": int(window.Seconds()),
			})
			return
		}
		c.Next()
	}
}

func (rl *RateLimiter) LimitByUser(key string, limit int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := GetUserID(c)
		if !ok {
			c.Next()
			return
		}
		rkey := fmt.Sprintf("rl:%s:user:%s", key, userID.String())
		ctx := context.Background()

		now := time.Now().UnixMilli()
		windowMs := window.Milliseconds()

		pipe := rl.rdb.Pipeline()
		pipe.ZRemRangeByScore(ctx, rkey, "0", fmt.Sprintf("%d", now-windowMs))
		pipe.ZAdd(ctx, rkey, redis.Z{Score: float64(now), Member: fmt.Sprintf("%d", now)})
		pipe.ZCard(ctx, rkey)
		pipe.Expire(ctx, rkey, window)

		results, _ := pipe.Exec(ctx)
		count := results[2].(*redis.IntCmd).Val()

		if count > int64(limit) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}
		c.Next()
	}
}

// ─── Security Headers ─────────────────────────────────────────────────────────

func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		c.Next()
	}
}

// ─── IP Whitelist ─────────────────────────────────────────────────────────────

func IPWhitelist(whitelist []string) gin.HandlerFunc {
	if len(whitelist) == 0 {
		return func(c *gin.Context) { c.Next() }
	}
	allowed := make(map[string]bool, len(whitelist))
	for _, ip := range whitelist {
		allowed[ip] = true
	}
	return func(c *gin.Context) {
		if !allowed[c.ClientIP()] {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "ip not allowed"})
			return
		}
		c.Next()
	}
}

// ─── Request ID ───────────────────────────────────────────────────────────────

func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		reqID := c.GetHeader("X-Request-ID")
		if reqID == "" {
			reqID = uuid.NewString()
		}
		c.Set("request_id", reqID)
		c.Header("X-Request-ID", reqID)
		c.Next()
	}
}

// ─── Logger Middleware ────────────────────────────────────────────────────────

func Logger(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		duration := time.Since(start)
		log.Info("request",
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.String("query", query),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("duration", duration),
			zap.String("ip", c.ClientIP()),
			zap.String("request_id", c.GetString("request_id")),
		)
	}
}

// ─── Risk Scorer ──────────────────────────────────────────────────────────────

type RiskScorer struct {
	rdb *redis.Client
	cfg *config.SecurityConfig
}

func NewRiskScorer(rdb *redis.Client, cfg *config.SecurityConfig) *RiskScorer {
	return &RiskScorer{rdb: rdb, cfg: cfg}
}

func (rs *RiskScorer) Score(c *gin.Context) float32 {
	var score float32

	// New IP
	ip := c.ClientIP()
	ua := c.GetHeader("User-Agent")
	if ip == "" || ua == "" {
		score += 0.3
	}

	// Unusual hour
	hour := time.Now().UTC().Hour()
	if hour < 6 || hour > 22 {
		score += 0.1
	}

	// Tor/VPN detection (simplified - check against known IP ranges in production)
	_ = ip

	// High request rate
	ctx := context.Background()
	rkey := fmt.Sprintf("req:count:%s", ip)
	count, _ := rs.rdb.Incr(ctx, rkey).Result()
	rs.rdb.Expire(ctx, rkey, time.Minute)
	if count > 30 {
		score += 0.4
	}

	if score > 1.0 {
		score = 1.0
	}
	return score
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
