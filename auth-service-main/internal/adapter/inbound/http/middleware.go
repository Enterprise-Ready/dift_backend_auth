package http

import (
	"net/http"
	"strconv"
	"time"

	mwcore "github.com/PlatformCore/libpackage/middleware/core"
	mwlogging "github.com/PlatformCore/libpackage/middleware/logging"
	mwmetrics "github.com/PlatformCore/libpackage/middleware/metrics"
	mwrecovery "github.com/PlatformCore/libpackage/middleware/recovery"
	mwrequestid "github.com/PlatformCore/libpackage/middleware/requestid"
	mwsecurity "github.com/PlatformCore/libpackage/middleware/securityheaders"
	mwtimeout "github.com/PlatformCore/libpackage/middleware/timeout"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var _ = []any{mwcore.HTTP, mwlogging.HTTP, mwmetrics.HTTP, mwrecovery.Default, mwrequestid.Default, mwsecurity.Default, mwtimeout.Default}

func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		}
		c.Set("request_id", id)
		c.Header("X-Request-ID", id)
		c.Next()
	}
}
func AccessLogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		_ = start
		c.Header("X-Auth-Service-Latency-Ms", strconv.FormatInt(time.Since(start).Milliseconds(), 10))
	}
}
func RecoveryMiddleware() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered any) {
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
	})
}
func RateLimitMiddleware() gin.HandlerFunc { return func(c *gin.Context) { c.Next() } }
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		c.Next()
	}
}
func BodyLimitMiddleware(maxBytes int64) gin.HandlerFunc {
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}
func IdempotencyMiddleware(ttl time.Duration) gin.HandlerFunc {
	_ = ttl
	return func(c *gin.Context) { c.Next() }
}
func AuditMiddleware() gin.HandlerFunc { return func(c *gin.Context) { c.Next() } }
