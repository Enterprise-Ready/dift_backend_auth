//go:build legacy
// +build legacy

package apikey

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/enterprise/auth-engine/internal/crypto"
	"github.com/enterprise/auth-engine/internal/middleware"
	"github.com/enterprise/auth-engine/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ─── Repository ───────────────────────────────────────────────────────────────

type Repository interface {
	Create(ctx context.Context, key *models.APIKey) error
	GetByHash(ctx context.Context, keyHash string) (*models.APIKey, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.APIKey, error)
	Revoke(ctx context.Context, id uuid.UUID, userID uuid.UUID) error
	Touch(ctx context.Context, id uuid.UUID) error
}

// ─── Service ──────────────────────────────────────────────────────────────────

type Service struct {
	repo Repository
	log  *zap.Logger
}

func NewService(repo Repository, log *zap.Logger) *Service {
	return &Service{repo: repo, log: log}
}

type CreateAPIKeyRequest struct {
	Name        string     `json:"name" validate:"required,min=2,max=64"`
	Permissions []string   `json:"permissions"`
	Scopes      []string   `json:"scopes"`
	RateLimit   int        `json:"rate_limit"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type CreateAPIKeyResponse struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	Key        string     `json:"key"` // shown ONCE
	Prefix     string     `json:"prefix"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

func (s *Service) Create(ctx context.Context, userID uuid.UUID, req *CreateAPIKeyRequest) (*CreateAPIKeyResponse, error) {
	plaintext, hash, err := crypto.GenerateAPIKey()
	if err != nil {
		return nil, fmt.Errorf("generate api key: %w", err)
	}

	prefix := crypto.ExtractAPIKeyPrefix(plaintext)
	rl := req.RateLimit
	if rl == 0 {
		rl = 1000
	}

	key := &models.APIKey{
		UserID:      userID,
		Name:        req.Name,
		KeyHash:     hash,
		Prefix:      prefix,
		Permissions: req.Permissions,
		Scopes:      req.Scopes,
		RateLimit:   rl,
		ExpiresAt:   req.ExpiresAt,
		IsActive:    true,
	}
	if err := s.repo.Create(ctx, key); err != nil {
		return nil, fmt.Errorf("store api key: %w", err)
	}

	s.log.Info("api key created", zap.String("user_id", userID.String()), zap.String("name", req.Name))

	return &CreateAPIKeyResponse{
		ID:        key.ID,
		Name:      key.Name,
		Key:       plaintext,
		Prefix:    prefix,
		ExpiresAt: key.ExpiresAt,
		CreatedAt: key.CreatedAt,
	}, nil
}

func (s *Service) Authenticate(ctx context.Context, rawKey string) (*models.APIKey, error) {
	if !strings.HasPrefix(rawKey, crypto.APIKeyPrefix) {
		return nil, ErrInvalidAPIKey
	}
	hash := crypto.HashAPIKey(rawKey)
	key, err := s.repo.GetByHash(ctx, hash)
	if err != nil {
		return nil, ErrInvalidAPIKey
	}
	if !key.IsActive {
		return nil, ErrAPIKeyRevoked
	}
	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return nil, ErrAPIKeyExpired
	}
	_ = s.repo.Touch(ctx, key.ID)
	return key, nil
}

func (s *Service) List(ctx context.Context, userID uuid.UUID) ([]*models.APIKey, error) {
	return s.repo.ListByUser(ctx, userID)
}

func (s *Service) Revoke(ctx context.Context, id uuid.UUID, userID uuid.UUID) error {
	return s.repo.Revoke(ctx, id, userID)
}

// ─── Middleware ───────────────────────────────────────────────────────────────

func AuthMiddleware(svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("X-API-Key")
		if header == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing X-API-Key header"})
			return
		}

		key, err := svc.Authenticate(c.Request.Context(), header)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		c.Set("api_key_id", key.ID)
		c.Set("api_key_user_id", key.UserID)
		c.Set("api_key_permissions", key.Permissions)
		c.Set("api_key_scopes", key.Scopes)
		c.Next()
	}
}

// ─── Handler ──────────────────────────────────────────────────────────────────

type Handler struct {
	svc *Service
	log *zap.Logger
}

func NewHandler(svc *Service, log *zap.Logger) *Handler {
	return &Handler{svc: svc, log: log}
}

func (h *Handler) RegisterRoutes(r *gin.RouterGroup, jwtMid gin.HandlerFunc) {
	authed := r.Group("/api-keys", jwtMid)
	authed.POST("", h.Create)
	authed.GET("", h.List)
	authed.DELETE("/:id", h.Revoke)
}

func (h *Handler) Create(c *gin.Context) {
	userID, _ := middleware.GetUserID(c)
	var req CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	resp, err := h.svc.Create(c.Request.Context(), userID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, resp)
}

func (h *Handler) List(c *gin.Context) {
	userID, _ := middleware.GetUserID(c)
	keys, err := h.svc.List(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"keys": keys})
}

func (h *Handler) Revoke(c *gin.Context) {
	userID, _ := middleware.GetUserID(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := h.svc.Revoke(c.Request.Context(), id, userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "api key revoked"})
}

// ─── Errors ───────────────────────────────────────────────────────────────────

var (
	ErrInvalidAPIKey = errors.New("invalid api key")
	ErrAPIKeyRevoked = errors.New("api key revoked")
	ErrAPIKeyExpired = errors.New("api key expired")
)
