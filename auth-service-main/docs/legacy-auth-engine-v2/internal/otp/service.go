//go:build legacy
// +build legacy

package otp

import (
	"context"
	"fmt"
	"time"

	"github.com/enterprise/auth-engine/internal/config"
	"github.com/enterprise/auth-engine/internal/crypto"
	"github.com/enterprise/auth-engine/internal/models"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
)

type Storer interface {
	Create(ctx context.Context, otp *models.OTP) error
	GetValid(ctx context.Context, recipient string, purpose models.OTPPurpose) (*models.OTP, error)
	IncrAttempts(ctx context.Context, id uuid.UUID) error
	MarkVerified(ctx context.Context, id uuid.UUID) error
	InvalidateAll(ctx context.Context, userID uuid.UUID, purpose models.OTPPurpose) error
}

type Notifier interface {
	SendEmailOTP(ctx context.Context, to, code string, purpose models.OTPPurpose) error
	SendSMSOTP(ctx context.Context, to, code string, purpose models.OTPPurpose) error
}

type Service struct {
	cfg    *config.OTPConfig
	store  Storer
	notify Notifier
	log    *zap.Logger
}

func NewService(cfg *config.OTPConfig, store Storer, notify Notifier, log *zap.Logger) *Service {
	return &Service{cfg: cfg, store: store, notify: notify, log: log}
}

// ─── Send OTP ──────────────────────────────────────────────────────────────────

func (s *Service) Send(ctx context.Context, userID uuid.UUID, req *models.SendOTPRequest) error {
	code, err := crypto.GenerateOTP(s.cfg.Length)
	if err != nil {
		return fmt.Errorf("generate otp: %w", err)
	}

	// Invalidate previous OTPs for same purpose
	_ = s.store.InvalidateAll(ctx, userID, req.Purpose)

	record := &models.OTP{
		UserID:    userID,
		Code:      code,
		Purpose:   req.Purpose,
		Channel:   req.Channel,
		Recipient: req.Recipient,
		ExpiresAt: time.Now().Add(s.cfg.Expiry),
	}
	if err := s.store.Create(ctx, record); err != nil {
		return fmt.Errorf("store otp: %w", err)
	}

	switch req.Channel {
	case models.OTPChannelEmail:
		if err := s.notify.SendEmailOTP(ctx, req.Recipient, code, req.Purpose); err != nil {
			return fmt.Errorf("send email otp: %w", err)
		}
	case models.OTPChannelSMS:
		if err := s.notify.SendSMSOTP(ctx, req.Recipient, code, req.Purpose); err != nil {
			return fmt.Errorf("send sms otp: %w", err)
		}
	default:
		return fmt.Errorf("unsupported otp channel: %s", req.Channel)
	}

	s.log.Info("otp sent",
		zap.String("channel", string(req.Channel)),
		zap.String("purpose", string(req.Purpose)),
		zap.String("user_id", userID.String()),
	)
	return nil
}

// ─── Verify OTP ────────────────────────────────────────────────────────────────

func (s *Service) Verify(ctx context.Context, req *models.VerifyOTPRequest) error {
	record, err := s.store.GetValid(ctx, req.Recipient, req.Purpose)
	if err != nil {
		return ErrOTPNotFound
	}

	if time.Now().After(record.ExpiresAt) {
		return ErrOTPExpired
	}
	if record.Attempts >= s.cfg.MaxAttempts {
		return ErrOTPMaxAttempts
	}

	_ = s.store.IncrAttempts(ctx, record.ID)

	if record.Code != req.Code {
		return ErrOTPInvalid
	}

	return s.store.MarkVerified(ctx, record.ID)
}

// ─── TOTP ─────────────────────────────────────────────────────────────────────

func (s *Service) GenerateTOTPSecret(userEmail string) (secret, qrURL string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.cfg.TOTPIssuer,
		AccountName: userEmail,
	})
	if err != nil {
		return "", "", fmt.Errorf("generate totp: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

func (s *Service) ValidateTOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}

func (s *Service) ValidateTOTPWithWindow(secret, code string, window uint) bool {
	return totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      window,
		Digits:    6,
		Algorithm: 0,
	}) == nil
}

// ─── Errors ───────────────────────────────────────────────────────────────────

var (
	ErrOTPNotFound    = fmt.Errorf("otp not found")
	ErrOTPExpired     = fmt.Errorf("otp expired")
	ErrOTPInvalid     = fmt.Errorf("otp invalid")
	ErrOTPMaxAttempts = fmt.Errorf("max otp attempts reached")
)
