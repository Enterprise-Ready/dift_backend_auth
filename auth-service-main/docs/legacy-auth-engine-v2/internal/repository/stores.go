//go:build legacy
// +build legacy

package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/enterprise/auth-engine/internal/models"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// ─── Common Errors ────────────────────────────────────────────────────────────

var ErrNotFound = errors.New("record not found")

// ─── OTP Store (Redis) ────────────────────────────────────────────────────────

type OTPStore struct {
	rdb *redis.Client
}

func NewOTPStore(rdb *redis.Client) *OTPStore {
	return &OTPStore{rdb: rdb}
}

func otpKey(recipient string, purpose models.OTPPurpose) string {
	return fmt.Sprintf("otp:%s:%s", purpose, recipient)
}

func (s *OTPStore) Create(ctx context.Context, otp *models.OTP) error {
	otp.ID = uuid.New()
	data, err := json.Marshal(otp)
	if err != nil {
		return err
	}
	ttl := time.Until(otp.ExpiresAt)
	return s.rdb.Set(ctx, otpKey(otp.Recipient, otp.Purpose), data, ttl).Err()
}

func (s *OTPStore) GetValid(ctx context.Context, recipient string, purpose models.OTPPurpose) (*models.OTP, error) {
	data, err := s.rdb.Get(ctx, otpKey(recipient, purpose)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var otp models.OTP
	if err := json.Unmarshal(data, &otp); err != nil {
		return nil, err
	}
	return &otp, nil
}

func (s *OTPStore) IncrAttempts(ctx context.Context, id uuid.UUID) error {
	// Re-fetch by scanning all OTP keys that match the ID
	// In practice: maintain a secondary key "otp:id:<uuid>" with attempts counter
	attKey := fmt.Sprintf("otp:att:%s", id.String())
	return s.rdb.Incr(ctx, attKey).Err()
}

func (s *OTPStore) MarkVerified(ctx context.Context, id uuid.UUID) error {
	// Mark in Redis, or just delete the OTP so it can't be reused
	verKey := fmt.Sprintf("otp:ver:%s", id.String())
	return s.rdb.Set(ctx, verKey, "1", 5*time.Minute).Err()
}

func (s *OTPStore) InvalidateAll(ctx context.Context, userID uuid.UUID, purpose models.OTPPurpose) error {
	pattern := fmt.Sprintf("otp:%s:*", purpose)
	keys, err := s.rdb.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		return s.rdb.Del(ctx, keys...).Err()
	}
	return nil
}

// ─── OAuth Provider Repository ─────────────────────────────────────────────────

type OAuthRepository struct {
	db *gorm.DB
}

func NewOAuthRepository(db *gorm.DB) *OAuthRepository {
	return &OAuthRepository{db: db}
}

func (r *OAuthRepository) Create(ctx context.Context, op *models.OAuthProvider) error {
	return r.db.WithContext(ctx).Create(op).Error
}

func (r *OAuthRepository) GetByProvider(ctx context.Context, provider, uid string) (*models.OAuthProvider, error) {
	var op models.OAuthProvider
	err := r.db.WithContext(ctx).
		Where("provider = ? AND provider_uid = ?", provider, uid).
		First(&op).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &op, err
}

func (r *OAuthRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*models.OAuthProvider, error) {
	var ops []*models.OAuthProvider
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&ops).Error
	return ops, err
}

func (r *OAuthRepository) Delete(ctx context.Context, userID uuid.UUID, provider string) error {
	return r.db.WithContext(ctx).
		Where("user_id = ? AND provider = ?", userID, provider).
		Delete(&models.OAuthProvider{}).Error
}

// ─── Face Store ───────────────────────────────────────────────────────────────

type FaceStore struct {
	db *gorm.DB
}

func NewFaceStore(db *gorm.DB) *FaceStore {
	return &FaceStore{db: db}
}

func (s *FaceStore) GetByUserID(ctx context.Context, userID uuid.UUID) (*models.FaceEnrollment, error) {
	var fe models.FaceEnrollment
	err := s.db.WithContext(ctx).
		Where("user_id = ? AND is_active = true", userID).
		First(&fe).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &fe, err
}

func (s *FaceStore) Save(ctx context.Context, enrollment *models.FaceEnrollment) error {
	return s.db.WithContext(ctx).Create(enrollment).Error
}

func (s *FaceStore) Deactivate(ctx context.Context, userID uuid.UUID) error {
	return s.db.WithContext(ctx).Model(&models.FaceEnrollment{}).
		Where("user_id = ?", userID).
		Update("is_active", false).Error
}

// ─── Audit Repository ─────────────────────────────────────────────────────────

type AuditRepository struct {
	db *gorm.DB
}

func NewAuditRepository(db *gorm.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

func (r *AuditRepository) Save(ctx context.Context, log *models.AuditLog) error {
	return r.db.WithContext(ctx).Create(log).Error
}

func (r *AuditRepository) Log(ctx context.Context, log *models.AuditLog) error {
	return r.Save(ctx, log)
}

func (r *AuditRepository) ListByUser(ctx context.Context, userID uuid.UUID, limit int) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Find(&logs).Error
	return logs, err
}

func (r *AuditRepository) ListByAction(ctx context.Context, action string, from, to time.Time) ([]*models.AuditLog, error) {
	var logs []*models.AuditLog
	err := r.db.WithContext(ctx).
		Where("action = ? AND created_at BETWEEN ? AND ?", action, from, to).
		Order("created_at DESC").
		Find(&logs).Error
	return logs, err
}

func (r *AuditRepository) DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	result := r.db.WithContext(ctx).
		Where("created_at < ?", cutoff).
		Delete(&models.AuditLog{})
	return result.RowsAffected, result.Error
}

// ─── API Key Repository ───────────────────────────────────────────────────────

type APIKeyRepository struct {
	db *gorm.DB
}

func NewAPIKeyRepository(db *gorm.DB) *APIKeyRepository {
	return &APIKeyRepository{db: db}
}

func (r *APIKeyRepository) Create(ctx context.Context, key *models.APIKey) error {
	return r.db.WithContext(ctx).Create(key).Error
}

func (r *APIKeyRepository) GetByHash(ctx context.Context, keyHash string) (*models.APIKey, error) {
	var key models.APIKey
	err := r.db.WithContext(ctx).
		Where("key_hash = ? AND is_active = true", keyHash).
		First(&key).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &key, err
}

func (r *APIKeyRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.APIKey, error) {
	var keys []*models.APIKey
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND is_active = true", userID).
		Order("created_at DESC").
		Find(&keys).Error
	return keys, err
}

func (r *APIKeyRepository) Revoke(ctx context.Context, id uuid.UUID, userID uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&models.APIKey{}).
		Where("id = ? AND user_id = ?", id, userID).
		Update("is_active", false).Error
}

func (r *APIKeyRepository) Touch(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	return r.db.WithContext(ctx).Model(&models.APIKey{}).
		Where("id = ?", id).
		Update("last_used_at", now).Error
}
