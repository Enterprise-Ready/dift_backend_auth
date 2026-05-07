package http

import (
	"context"
	"net/http"
	"strings"
	"time"

	repoport "dift_backend_go/auth-service/internal/interface/repository"

	"github.com/gin-gonic/gin"
)

type HealthHandler struct {
	identity repoport.IdentityGateway
}

func NewHealthHandler(identity repoport.IdentityGateway) *HealthHandler {
	return &HealthHandler{identity: identity}
}

func (h *HealthHandler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "auth-service"})
}

func (h *HealthHandler) Ready(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()
	if err := h.identity.Health(ctx); err != nil {
		writeError(c, http.StatusServiceUnavailable, "dependency_unavailable", "identity service unavailable")
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}

func AuthBearerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authz := strings.TrimSpace(c.GetHeader("Authorization"))
		if authz == "" || !strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			writeError(c, http.StatusUnauthorized, "unauthorized", "missing bearer token")
			c.Abort()
			return
		}
		token := strings.TrimSpace(authz[7:])
		if token == "" {
			writeError(c, http.StatusUnauthorized, "unauthorized", "invalid bearer token")
			c.Abort()
			return
		}
		c.Set("access_token", token)
		c.Next()
	}
}
