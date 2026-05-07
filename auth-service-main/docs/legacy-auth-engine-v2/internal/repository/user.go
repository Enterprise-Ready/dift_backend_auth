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

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	return r.db.WithContext(ctx).Create(user).Error
}

func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("id = ? AND deleted_at IS NULL", id).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &user, err
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("email = ? AND deleted_at IS NULL", email).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &user, err
}

func (r *UserRepository) GetByPhone(ctx context.Context, phone string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).Where("phone = ? AND deleted_at IS NULL", phone).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &user, err
}

func (r *UserRepository) GetByIdentifier(ctx context.Context, identifier string) (*models.User, error) {
	var user models.User
	err := r.db.WithContext(ctx).
		Where("(email = ? OR phone = ?) AND deleted_at IS NULL", identifier, identifier).
		First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &user, err
}

func (r *UserRepository) Update(ctx context.Context, user *models.User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

func (r *UserRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", id).
		Update("deleted_at", now).Error
}

func (r *UserRepository) IncrFailedLogin(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", id).
		UpdateColumn("failed_login_count", gorm.Expr("failed_login_count + 1")).Error
}

func (r *UserRepository) ResetFailedLogin(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"failed_login_count": 0,
			"locked_until":       nil,
		}).Error
}

func (r *UserRepository) LockAccount(ctx context.Context, id uuid.UUID, until time.Time) error {
	return r.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", id).
		Update("locked_until", until).Error
}

func (r *UserRepository) MarkEmailVerified(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"email_verified": true,
			"status":         models.UserStatusActive,
		}).Error
}

func (r *UserRepository) MarkPhoneVerified(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"phone_verified": true,
			"status":         models.UserStatusActive,
		}).Error
}

func (r *UserRepository) ListAll(ctx context.Context, offset, limit int) ([]*models.User, int64, error) {
	var users []*models.User
	var count int64
	r.db.WithContext(ctx).Model(&models.User{}).Where("deleted_at IS NULL").Count(&count)
	err := r.db.WithContext(ctx).
		Where("deleted_at IS NULL").
		Order("created_at DESC").
		Offset(offset).Limit(limit).
		Find(&users).Error
	return users, count, err
}
