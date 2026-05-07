package http

import (
	"net/http"
	"strconv"
	"time"

	enterpriseaudit "dift_backend_go/auth-service/internal/servicecore/enterprise/audit"
	"github.com/gin-gonic/gin"
)

var authEnterpriseAuditLogger = enterpriseaudit.NewLogger(
	enterpriseaudit.NewConsoleSink(),
	enterpriseaudit.LoggerConfig{
		ServiceName:     "auth-service",
		SensitiveFields: []string{"password", "token", "secret", "authorization", "refresh_token"},
		EnableHashChain: true,
	},
)

func AuditMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		ctx := enterpriseaudit.WithAuditContext(c.Request.Context(), enterpriseaudit.AuditMeta{
			UserID:        c.GetString("user_id"),
			RequestID:     c.GetString("request_id"),
			CorrelationID: coalesce(c.GetHeader("X-Correlation-ID"), c.GetString("request_id")),
			ServiceName:   "auth-service",
			IPAddress:     c.ClientIP(),
			UserAgent:     c.Request.UserAgent(),
		})
		c.Request = c.Request.WithContext(ctx)
		c.Next()

		if isSafeMethod(c.Request.Method) && c.Writer.Status() < http.StatusBadRequest {
			return
		}

		status := c.Writer.Status()
		opts := []enterpriseaudit.EntryOption{
			enterpriseaudit.WithCategory(enterpriseaudit.CategoryAuth),
			enterpriseaudit.WithAction(auditActionFromMethod(c.Request.Method)),
			enterpriseaudit.WithOutcome(auditOutcomeFromStatus(status)),
			enterpriseaudit.WithSeverity(auditSeverityFromStatus(status)),
			enterpriseaudit.WithOperation(routeOrPath(c)),
			enterpriseaudit.WithResource("http_route", routeOrPath(c)),
			enterpriseaudit.WithDuration(time.Since(start)),
			enterpriseaudit.WithMetadata("method", c.Request.Method),
			enterpriseaudit.WithMetadata("status", strconv.Itoa(status)),
		}
		if status >= http.StatusBadRequest {
			opts = append(opts, enterpriseaudit.WithMetadata("error", http.StatusText(status)))
		}
		authEnterpriseAuditLogger.LogEvent(ctx, opts...)
	}
}

func routeOrPath(c *gin.Context) string {
	if path := c.FullPath(); path != "" {
		return path
	}
	return c.Request.URL.Path
}

func auditActionFromMethod(method string) enterpriseaudit.Action {
	switch method {
	case http.MethodPost:
		return enterpriseaudit.ActionCreate
	case http.MethodPut, http.MethodPatch:
		return enterpriseaudit.ActionUpdate
	case http.MethodDelete:
		return enterpriseaudit.ActionDelete
	default:
		return enterpriseaudit.ActionRead
	}
}

func auditOutcomeFromStatus(status int) enterpriseaudit.Outcome {
	switch {
	case status >= http.StatusOK && status < http.StatusMultipleChoices:
		return enterpriseaudit.OutcomeSuccess
	case status == http.StatusForbidden || status == http.StatusUnauthorized:
		return enterpriseaudit.OutcomeDenied
	default:
		return enterpriseaudit.OutcomeFailure
	}
}

func auditSeverityFromStatus(status int) enterpriseaudit.Severity {
	switch {
	case status >= http.StatusInternalServerError:
		return enterpriseaudit.SeverityCritical
	case status >= http.StatusBadRequest:
		return enterpriseaudit.SeverityWarning
	default:
		return enterpriseaudit.SeverityInfo
	}
}

func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func coalesce(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
