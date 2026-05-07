//go:build legacy
// +build legacy

package admin

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/enterprise/auth-engine/internal/audit"
	"github.com/enterprise/auth-engine/internal/middleware"
	"github.com/enterprise/auth-engine/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ─── UserAdmin Repository ─────────────────────────────────────────────────────

type UserAdminRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	ListAll(ctx context.Context, offset, limit int) ([]*models.User, int64, error)
	Update(ctx context.Context, user *models.User) error
	LockAccount(ctx context.Context, id uuid.UUID, until time.Time) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
}

type SessionAdminRepo interface {
	ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.Session, error)
	RevokeAll(ctx context.Context, userID uuid.UUID) error
}

// ─── Handler ──────────────────────────────────────────────────────────────────

type Handler struct {
	users    UserAdminRepo
	sessions SessionAdminRepo
	audits   *audit.Service
	log      *zap.Logger
}

func NewHandler(users UserAdminRepo, sessions SessionAdminRepo, audits *audit.Service, log *zap.Logger) *Handler {
	return &Handler{
		users:    users,
		sessions: sessions,
		audits:   audits,
		log:      log,
	}
}

func (h *Handler) RegisterRoutes(r *gin.RouterGroup, jwtMid gin.HandlerFunc, ipWhitelist gin.HandlerFunc) {
	admin := r.Group("/admin", jwtMid, middleware.RequireRole("admin", "superadmin"), ipWhitelist)

	admin.GET("/users", h.ListUsers)
	admin.GET("/users/:id", h.GetUser)
	admin.PATCH("/users/:id/status", h.UpdateUserStatus)
	admin.POST("/users/:id/lock", h.LockUser)
	admin.POST("/users/:id/unlock", h.UnlockUser)
	admin.DELETE("/users/:id", h.DeleteUser)
	admin.GET("/users/:id/sessions", h.GetUserSessions)
	admin.DELETE("/users/:id/sessions", h.RevokeUserSessions)
	admin.GET("/users/:id/audit", h.GetUserAuditLog)
	admin.GET("/audit", h.GetAuditLog)
	admin.GET("/stats", h.GetStats)
}

// GET /admin/users?page=1&limit=20
func (h *Handler) ListUsers(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if page < 1 {
		page = 1
	}
	if limit > 100 {
		limit = 100
	}
	offset := (page - 1) * limit

	users, total, err := h.users.ListAll(c.Request.Context(), offset, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
		"pagination": gin.H{
			"page":  page,
			"limit": limit,
			"total": total,
			"pages": (total + int64(limit) - 1) / int64(limit),
		},
	})
}

// GET /admin/users/:id
func (h *Handler) GetUser(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}
	user, err := h.users.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, user)
}

// PATCH /admin/users/:id/status
func (h *Handler) UpdateUserStatus(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	var body struct {
		Status models.UserStatus `json:"status" validate:"required,oneof=active inactive suspended"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.users.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	user.Status = body.Status
	if err := h.users.Update(c.Request.Context(), user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "status updated", "status": body.Status})
}

// POST /admin/users/:id/lock
func (h *Handler) LockUser(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	var body struct {
		Duration string `json:"duration"` // e.g. "24h", "permanent"
		Reason   string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body)

	var until time.Time
	if body.Duration == "permanent" || body.Duration == "" {
		until = time.Now().Add(100 * 365 * 24 * time.Hour)
	} else {
		dur, err := time.ParseDuration(body.Duration)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid duration"})
			return
		}
		until = time.Now().Add(dur)
	}

	if err := h.users.LockAccount(c.Request.Context(), id, until); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Revoke all sessions
	_ = h.sessions.RevokeAll(c.Request.Context(), id)

	c.JSON(http.StatusOK, gin.H{"message": "account locked", "until": until})
}

// POST /admin/users/:id/unlock
func (h *Handler) UnlockUser(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	user, err := h.users.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	user.LockedUntil = nil
	user.FailedLoginCount = 0
	if err := h.users.Update(c.Request.Context(), user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "account unlocked"})
}

// DELETE /admin/users/:id
func (h *Handler) DeleteUser(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	if err := h.users.SoftDelete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_ = h.sessions.RevokeAll(c.Request.Context(), id)

	c.JSON(http.StatusOK, gin.H{"message": "user deleted"})
}

// GET /admin/users/:id/sessions
func (h *Handler) GetUserSessions(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	sessions, err := h.sessions.ListByUser(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

// DELETE /admin/users/:id/sessions
func (h *Handler) RevokeUserSessions(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}
	_ = h.sessions.RevokeAll(c.Request.Context(), id)
	c.JSON(http.StatusOK, gin.H{"message": "all sessions revoked"})
}

// GET /admin/users/:id/audit
func (h *Handler) GetUserAuditLog(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	logs, err := h.audits.GetUserHistory(c.Request.Context(), id, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"logs": logs})
}

// GET /admin/audit?action=login&from=...&to=...
func (h *Handler) GetAuditLog(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "audit log endpoint - add date range filters"})
}

// GET /admin/stats
func (h *Handler) GetStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message":   "stats endpoint",
		"timestamp": time.Now().UTC(),
	})
}
