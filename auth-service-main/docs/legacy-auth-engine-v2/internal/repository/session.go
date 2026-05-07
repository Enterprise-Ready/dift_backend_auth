//go:build legacy
// +build legacy

package repository

import (
	"context"
	"errors"
	"time"

	"github.com/enterprise/auth-engine/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type SessionRepository struct {
	db *gorm.DB
}

func NewSessionRepository(db *gorm.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func (r *SessionRepository) Create(ctx context.Context, session *models.Session) error {
	return r.db.WithContext(ctx).Create(session).Error
}

func (r *SessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Session, error) {
	var session models.Session
	err := r.db.WithContext(ctx).Where("id = ? AND is_active = true", id).First(&session).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &session, err
}

func (r *SessionRepository) GetByRefreshToken(ctx context.Context, token string) (*models.Session, error) {
	var session models.Session
	err := r.db.WithContext(ctx).Where("refresh_token = ? AND is_active = true", token).First(&session).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &session, err
}

func (r *SessionRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
	var sessions []*models.Session
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND is_active = true AND expires_at > ?", userID, time.Now()).
		Order("last_seen_at DESC").
		Find(&sessions).Error
	return sessions, err
}

func (r *SessionRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&models.Session{}).
		Where("id = ?", id).
		Update("is_active", false).Error
}

func (r *SessionRepository) RevokeAll(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&models.Session{}).
		Where("user_id = ?", userID).
		Update("is_active", false).Error
}

func (r *SessionRepository) Touch(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&models.Session{}).
		Where("id = ?", id).
		Update("last_seen_at", time.Now()).Error
}

func (r *SessionRepository) CountActive(ctx context.Context, userID uuid.UUID) (int, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.Session{}).
		Where("user_id = ? AND is_active = true AND expires_at > ?", userID, time.Now()).
		Count(&count).Error
	return int(count), err
}

func (r *SessionRepository) CleanupExpired(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).Model(&models.Session{}).
		Where("expires_at < ? OR is_active = false", time.Now().Add(-24*time.Hour)).
		Delete(&models.Session{})
	return result.RowsAffected, result.Error
}
