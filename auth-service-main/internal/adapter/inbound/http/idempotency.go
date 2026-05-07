package http

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"time"

	enterpriseidempotency "dift_backend_go/auth-service/internal/servicecore/enterprise/idempotency"
	"github.com/gin-gonic/gin"
)

type cachedHTTPResponse struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
}

var authEnterpriseIdempotency = enterpriseidempotency.NewManager(
	enterpriseidempotency.NewMemoryStore(),
	enterpriseidempotency.Config{
		DefaultTTL:         10 * time.Minute,
		DefaultNamespace:   "http",
		ServiceName:        "auth-service",
		StrictPayloadCheck: true,
		MaxRetryAttempts:   1,
		LockTTL:            30 * time.Second,
	},
)

func IdempotencyMiddleware(ttl time.Duration) gin.HandlerFunc {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return func(c *gin.Context) {
		if !isMutatingMethod(c.Request.Method) {
			c.Next()
			return
		}

		key := c.GetHeader("Idempotency-Key")
		if key == "" {
			c.Next()
			return
		}

		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			writeError(c, http.StatusBadRequest, "invalid_request_body", "failed to read request body")
			c.Abort()
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		route := routeOrPath(c)
		namespace := "http"
		result, err := authEnterpriseIdempotency.Evaluate(c.Request.Context(), &enterpriseidempotency.Request{
			Key:           key,
			Namespace:     namespace,
			Payload:       map[string]any{"method": c.Request.Method, "route": route, "body": string(bodyBytes)},
			UserID:        c.GetString("user_id"),
			ServiceName:   "auth-service",
			OperationName: route,
			Metadata:      map[string]string{"method": c.Request.Method, "route": route},
			TTL:           ttl,
		})
		if err != nil {
			switch {
			case errors.Is(err, enterpriseidempotency.ErrKeyConflict):
				writeError(c, http.StatusConflict, "idempotency_conflict", "idempotency key was reused with a different payload")
			case errors.Is(err, enterpriseidempotency.ErrRequestInFlight):
				writeError(c, http.StatusConflict, "idempotency_in_flight", "an identical request is already being processed")
			default:
				writeError(c, http.StatusInternalServerError, "idempotency_failed", "failed to evaluate idempotency state")
			}
			c.Abort()
			return
		}

		if result.IsCached {
			var cached cachedHTTPResponse
			if _, ok, cacheErr := authEnterpriseIdempotency.GetCachedResponse(c.Request.Context(), namespace, key, &cached); cacheErr == nil && ok {
				contentType := cached.ContentType
				if contentType == "" {
					contentType = "application/json"
				}
				c.Data(cached.Status, contentType, []byte(cached.Body))
				c.Abort()
				return
			}
			c.Status(result.Record.HTTPStatus)
			c.Abort()
			return
		}

		bw := &bodyWriter{ResponseWriter: c.Writer}
		c.Writer = bw
		c.Next()

		if c.Writer.Status() >= http.StatusInternalServerError {
			_ = authEnterpriseIdempotency.Fail(c.Request.Context(), namespace, key, http.StatusText(c.Writer.Status()))
			return
		}

		_ = authEnterpriseIdempotency.Complete(c.Request.Context(), namespace, key, cachedHTTPResponse{
			Status:      c.Writer.Status(),
			ContentType: c.Writer.Header().Get("Content-Type"),
			Body:        string(bw.body),
		}, c.Writer.Status())
	}
}

type bodyWriter struct {
	gin.ResponseWriter
	body []byte
}

func (w *bodyWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return w.ResponseWriter.Write(b)
}

func (w *bodyWriter) WriteString(s string) (int, error) {
	w.body = append(w.body, s...)
	return w.ResponseWriter.WriteString(s)
}

func isMutatingMethod(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
}
