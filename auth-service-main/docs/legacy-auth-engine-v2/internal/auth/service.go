//go:build legacy
// +build legacy

package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/enterprise/auth-engine/internal/config"
	"github.com/enterprise/auth-engine/internal/crypto"
	"github.com/enterprise/auth-engine/internal/face"
	"github.com/enterprise/auth-engine/internal/models"
	"github.com/enterprise/auth-engine/internal/oauth"
	"github.com/enterprise/auth-engine/internal/otp"
	jwtpkg "github.com/enterprise/auth-engine/pkg/jwt"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ─── Repository Interface ─────────────────────────────────────────────────────

type UserRepository interface {
	Create(ctx context.Context, user *models.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	GetByPhone(ctx context.Context, phone string) (*models.User, error)
	GetByIdentifier(ctx context.Context, identifier string) (*models.User, error)
	Update(ctx context.Context, user *models.User) error
	IncrFailedLogin(ctx context.Context, id uuid.UUID) error
	ResetFailedLogin(ctx context.Context, id uuid.UUID) error
	LockAccount(ctx context.Context, id uuid.UUID, until time.Time) error
}

type SessionRepository interface {
	Create(ctx context.Context, session *models.Session) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Session, error)
	GetByRefreshToken(ctx context.Context, token string) (*models.Session, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.Session, error)
	Revoke(ctx context.Context, id uuid.UUID) error
	RevokeAll(ctx context.Context, userID uuid.UUID) error
	Touch(ctx context.Context, id uuid.UUID) error
	CountActive(ctx context.Context, userID uuid.UUID) (int, error)
}

type OAuthRepository interface {
	Create(ctx context.Context, op *models.OAuthProvider) error
	GetByProvider(ctx context.Context, provider, uid string) (*models.OAuthProvider, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*models.OAuthProvider, error)
}

type AuditRepository interface {
	Log(ctx context.Context, entry *models.AuditLog) error
}

// ─── Composited Notifier ──────────────────────────────────────────────────────

type OTPNotifier interface {
	SendEmailOTP(ctx context.Context, to, code string, purpose models.OTPPurpose) error
	SendSMSOTP(ctx context.Context, to, code string, purpose models.OTPPurpose) error
}

// ─── Service ──────────────────────────────────────────────────────────────────

type Service struct {
	cfg      *config.Config
	users    UserRepository
	sessions SessionRepository
	oauths   OAuthRepository
	audits   AuditRepository
	otpSvc   *otp.Service
	faceSvc  *face.Service
	oauthReg *oauth.Registry
	jwt      *jwtpkg.Manager
	log      *zap.Logger
}

func NewService(
	cfg *config.Config,
	users UserRepository,
	sessions SessionRepository,
	oauths OAuthRepository,
	audits AuditRepository,
	otpSvc *otp.Service,
	faceSvc *face.Service,
	oauthReg *oauth.Registry,
	jwt *jwtpkg.Manager,
	log *zap.Logger,
) *Service {
	return &Service{
		cfg:      cfg,
		users:    users,
		sessions: sessions,
		oauths:   oauths,
		audits:   audits,
		otpSvc:   otpSvc,
		faceSvc:  faceSvc,
		oauthReg: oauthReg,
		jwt:      jwt,
		log:      log,
	}
}

// ─── Register ─────────────────────────────────────────────────────────────────

func (s *Service) Register(ctx context.Context, req *models.RegisterRequest, ip, ua string) (*models.User, error) {
	if err := s.validatePasswordStrength(req.Password); err != nil {
		return nil, err
	}

	// Check uniqueness
	if req.Email != nil {
		if existing, _ := s.users.GetByEmail(ctx, *req.Email); existing != nil {
			return nil, ErrEmailAlreadyExists
		}
	}
	if req.Phone != nil {
		if existing, _ := s.users.GetByPhone(ctx, *req.Phone); existing != nil {
			return nil, ErrPhoneAlreadyExists
		}
	}

	hash, err := crypto.HashPassword(req.Password, s.cfg.Security.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user := &models.User{
		Email:        req.Email,
		Phone:        req.Phone,
		PasswordHash: &hash,
		DisplayName:  req.DisplayName,
		Status:       models.UserStatusPending,
		Role:         "user",
	}
	if err := s.users.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	s.audit(ctx, &user.ID, "register", "user", ip, ua, "success", nil, 0)

	// Send verification
	if req.Email != nil {
		_ = s.otpSvc.Send(ctx, user.ID, &models.SendOTPRequest{
			Recipient: *req.Email,
			Channel:   models.OTPChannelEmail,
			Purpose:   models.OTPPurposeVerifyEmail,
		})
	} else if req.Phone != nil {
		_ = s.otpSvc.Send(ctx, user.ID, &models.SendOTPRequest{
			Recipient: *req.Phone,
			Channel:   models.OTPChannelSMS,
			Purpose:   models.OTPPurposeVerifyPhone,
		})
	}

	return user, nil
}

// ─── Login (password) ─────────────────────────────────────────────────────────

func (s *Service) Login(ctx context.Context, req *models.LoginRequest, ip, ua string) (*models.TokenResponse, error) {
	user, err := s.users.GetByIdentifier(ctx, req.Identifier)
	if err != nil {
		s.audit(ctx, nil, "login", "user", ip, ua, "failure", map[string]interface{}{"reason": "user_not_found"}, 0.8)
		return nil, ErrInvalidCredentials
	}

	// Lockout check
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return nil, ErrAccountLocked
	}

	// Status check
	if user.Status == models.UserStatusSuspended {
		return nil, ErrAccountSuspended
	}

	// Password check
	if user.PasswordHash == nil || !crypto.VerifyPassword(req.Password, *user.PasswordHash) {
		_ = s.users.IncrFailedLogin(ctx, user.ID)
		if user.FailedLoginCount+1 >= s.cfg.Security.MaxLoginAttempts {
			lockUntil := time.Now().Add(s.cfg.Security.LockoutDuration)
			_ = s.users.LockAccount(ctx, user.ID, lockUntil)
		}
		s.audit(ctx, &user.ID, "login", "user", ip, ua, "failure", map[string]interface{}{"reason": "invalid_password"}, 0.7)
		return nil, ErrInvalidCredentials
	}

	_ = s.users.ResetFailedLogin(ctx, user.ID)

	// MFA gate
	if user.MFAEnabled {
		if req.MFACode == nil {
			return &models.TokenResponse{MFARequired: true}, nil
		}
		if user.MFASecret != nil {
			if !s.otpSvc.ValidateTOTP(*user.MFASecret, *req.MFACode) {
				// Try backup codes
				if !s.verifyBackupCode(user, *req.MFACode) {
					s.audit(ctx, &user.ID, "mfa_verify", "user", ip, ua, "failure", nil, 0.9)
					return nil, ErrInvalidMFACode
				}
			}
		}
	}

	return s.issueTokens(ctx, user, req.DeviceInfo, ip, ua, true)
}

// ─── OAuth Login ──────────────────────────────────────────────────────────────

func (s *Service) OAuthLogin(ctx context.Context, req *models.OAuthLoginRequest, ip, ua string) (*models.TokenResponse, error) {
	provider, err := s.oauthReg.Get(req.Provider)
	if err != nil {
		return nil, fmt.Errorf("oauth provider: %w", err)
	}

	providerUser, err := provider.VerifyIDToken(ctx, req.Token)
	if err != nil {
		s.audit(ctx, nil, "oauth_login", req.Provider, ip, ua, "failure", map[string]interface{}{"error": err.Error()}, 0.5)
		return nil, fmt.Errorf("verify oauth token: %w", err)
	}

	// Find or create user
	oauthRecord, err := s.oauths.GetByProvider(ctx, req.Provider, providerUser.ProviderUID)
	var user *models.User

	if err != nil {
		// New OAuth user - create account
		user = &models.User{
			Email:         providerUser.Email,
			DisplayName:   providerUser.DisplayName,
			AvatarURL:     providerUser.AvatarURL,
			Status:        models.UserStatusActive,
			EmailVerified: providerUser.Verified,
			Role:          "user",
		}
		if err := s.users.Create(ctx, user); err != nil {
			return nil, fmt.Errorf("create oauth user: %w", err)
		}
		if err := s.oauths.Create(ctx, &models.OAuthProvider{
			UserID:      user.ID,
			Provider:    req.Provider,
			ProviderUID: providerUser.ProviderUID,
		}); err != nil {
			return nil, fmt.Errorf("store oauth link: %w", err)
		}
	} else {
		user, err = s.users.GetByID(ctx, oauthRecord.UserID)
		if err != nil {
			return nil, fmt.Errorf("get user: %w", err)
		}
	}

	if user.Status == models.UserStatusSuspended {
		return nil, ErrAccountSuspended
	}

	s.audit(ctx, &user.ID, "oauth_login", req.Provider, ip, ua, "success", nil, 0)
	return s.issueTokens(ctx, user, req.DeviceInfo, ip, ua, true)
}

// ─── Face Login ───────────────────────────────────────────────────────────────

func (s *Service) FaceLogin(ctx context.Context, req *models.FaceLoginRequest, ip, ua string) (*models.TokenResponse, error) {
	// Liveness check first
	live, score, err := s.faceSvc.CheckLiveness(req.ImageBase64)
	if err != nil || !live {
		return nil, face.ErrLivenessCheck
	}
	s.log.Info("liveness passed", zap.Float32("score", score))

	// We need the userID; in production the client sends a hint (email/phone)
	// or we match against all enrolled faces (expensive, use face search index)
	// For this engine: client sends identifier + face image together
	return nil, fmt.Errorf("face login: combine with identifier lookup then call FaceVerify")
}

func (s *Service) FaceVerify(ctx context.Context, userID uuid.UUID, imageBase64 string) (bool, error) {
	matched, similarity, err := s.faceSvc.Verify(ctx, userID, imageBase64)
	if err != nil {
		return false, err
	}
	s.log.Info("face verify result", zap.Bool("matched", matched), zap.Float32("similarity", similarity))
	return matched, nil
}

// ─── Refresh Token ────────────────────────────────────────────────────────────

func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (*models.TokenResponse, error) {
	claims, err := s.jwt.ParseRefreshToken(refreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}

	session, err := s.sessions.GetByID(ctx, claims.SessionID)
	if err != nil || !session.IsActive {
		return nil, ErrSessionExpired
	}

	if time.Now().After(session.ExpiresAt) {
		_ = s.sessions.Revoke(ctx, session.ID)
		return nil, ErrSessionExpired
	}

	user, err := s.users.GetByID(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	// Rotate refresh token
	newRefresh, err := s.jwt.GenerateRefreshToken(user.ID, session.ID)
	if err != nil {
		return nil, fmt.Errorf("generate refresh: %w", err)
	}

	newAccess, err := s.jwt.GenerateAccessToken(user.ID, session.ID, user.Role, user.Email, user.Phone, true)
	if err != nil {
		return nil, fmt.Errorf("generate access: %w", err)
	}

	_ = s.sessions.Touch(ctx, session.ID)

	return &models.TokenResponse{
		AccessToken:  newAccess,
		RefreshToken: newRefresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.jwt.AccessExpiry().Seconds()),
		SessionID:    session.ID,
	}, nil
}

// ─── OTP Auth ─────────────────────────────────────────────────────────────────

func (s *Service) SendOTP(ctx context.Context, userID uuid.UUID, req *models.SendOTPRequest) error {
	return s.otpSvc.Send(ctx, userID, req)
}

func (s *Service) VerifyOTP(ctx context.Context, req *models.VerifyOTPRequest) error {
	return s.otpSvc.Verify(ctx, req)
}

// ─── MFA Management ───────────────────────────────────────────────────────────

func (s *Service) EnableMFA(ctx context.Context, userID uuid.UUID, password string) (secret, qrURL string, backupCodes []string, err error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return "", "", nil, err
	}

	if user.PasswordHash != nil && !crypto.VerifyPassword(password, *user.PasswordHash) {
		return "", "", nil, ErrInvalidCredentials
	}

	email := ""
	if user.Email != nil {
		email = *user.Email
	}

	secret, qrURL, err = s.otpSvc.GenerateTOTPSecret(email)
	if err != nil {
		return "", "", nil, err
	}

	codes, hashes, err := crypto.GenerateBackupCodes(10)
	if err != nil {
		return "", "", nil, err
	}

	encSecret, err := crypto.Encrypt(secret, s.cfg.JWT.AccessSecret)
	if err != nil {
		return "", "", nil, err
	}

	user.MFASecret = &encSecret
	user.MFABackupCodes = hashes
	if err := s.users.Update(ctx, user); err != nil {
		return "", "", nil, err
	}

	return secret, qrURL, codes, nil
}

func (s *Service) ConfirmMFA(ctx context.Context, userID uuid.UUID, code string) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.MFASecret == nil {
		return fmt.Errorf("mfa not initialized")
	}

	secret, err := crypto.Decrypt(*user.MFASecret, s.cfg.JWT.AccessSecret)
	if err != nil {
		return fmt.Errorf("decrypt mfa secret: %w", err)
	}

	if !s.otpSvc.ValidateTOTP(secret, code) {
		return ErrInvalidMFACode
	}

	user.MFAEnabled = true
	return s.users.Update(ctx, user)
}

func (s *Service) DisableMFA(ctx context.Context, userID uuid.UUID, code string) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if !user.MFAEnabled || user.MFASecret == nil {
		return fmt.Errorf("mfa not enabled")
	}

	secret, _ := crypto.Decrypt(*user.MFASecret, s.cfg.JWT.AccessSecret)
	if !s.otpSvc.ValidateTOTP(secret, code) {
		return ErrInvalidMFACode
	}

	user.MFAEnabled = false
	user.MFASecret = nil
	user.MFABackupCodes = nil
	return s.users.Update(ctx, user)
}

// ─── Password ─────────────────────────────────────────────────────────────────

func (s *Service) RequestPasswordReset(ctx context.Context, identifier, ip, ua string) error {
	user, err := s.users.GetByIdentifier(ctx, identifier)
	if err != nil {
		return nil // Don't leak user existence
	}

	purpose := models.OTPPurposePasswordReset
	if user.Email != nil {
		return s.otpSvc.Send(ctx, user.ID, &models.SendOTPRequest{
			Recipient: *user.Email,
			Channel:   models.OTPChannelEmail,
			Purpose:   purpose,
		})
	} else if user.Phone != nil {
		return s.otpSvc.Send(ctx, user.ID, &models.SendOTPRequest{
			Recipient: *user.Phone,
			Channel:   models.OTPChannelSMS,
			Purpose:   purpose,
		})
	}
	return nil
}

func (s *Service) ResetPassword(ctx context.Context, identifier, token, newPassword, ip, ua string) error {
	if err := s.validatePasswordStrength(newPassword); err != nil {
		return err
	}

	if err := s.otpSvc.Verify(ctx, &models.VerifyOTPRequest{
		Recipient: identifier,
		Code:      token,
		Purpose:   models.OTPPurposePasswordReset,
	}); err != nil {
		return err
	}

	user, err := s.users.GetByIdentifier(ctx, identifier)
	if err != nil {
		return ErrUserNotFound
	}

	hash, err := crypto.HashPassword(newPassword, s.cfg.Security.BcryptCost)
	if err != nil {
		return err
	}

	now := time.Now()
	user.PasswordHash = &hash
	user.PasswordChangedAt = &now
	if err := s.users.Update(ctx, user); err != nil {
		return err
	}

	// Revoke all sessions on password reset
	_ = s.sessions.RevokeAll(ctx, user.ID)
	s.audit(ctx, &user.ID, "password_reset", "user", ip, ua, "success", nil, 0)
	return nil
}

// ─── Logout ───────────────────────────────────────────────────────────────────

func (s *Service) Logout(ctx context.Context, sessionID uuid.UUID) error {
	return s.sessions.Revoke(ctx, sessionID)
}

func (s *Service) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	return s.sessions.RevokeAll(ctx, userID)
}

// ─── Face Enrollment ──────────────────────────────────────────────────────────

func (s *Service) EnrollFace(ctx context.Context, userID uuid.UUID, req *models.EnrollFaceRequest) error {
	live, _, _ := s.faceSvc.CheckLiveness(req.ImageBase64)
	if !live {
		return face.ErrLivenessCheck
	}
	return s.faceSvc.Enroll(ctx, userID, req.ImageBase64)
}

// ─── Internal ─────────────────────────────────────────────────────────────────

func (s *Service) issueTokens(ctx context.Context, user *models.User, device models.DeviceInfo, ip, ua string, mfaDone bool) (*models.TokenResponse, error) {
	// Session limit
	count, _ := s.sessions.CountActive(ctx, user.ID)
	if count >= s.cfg.Security.SessionMaxDevices && s.cfg.Security.SessionMaxDevices > 0 {
		return nil, ErrSessionLimitReached
	}

	sessionID := uuid.New()
	accessToken, refreshToken, err := s.jwt.GenerateTokenPair(user.ID, sessionID, user.Role, user.Email, user.Phone, mfaDone)
	if err != nil {
		return nil, fmt.Errorf("generate tokens: %w", err)
	}

	session := &models.Session{
		ID:           sessionID,
		UserID:       user.ID,
		RefreshToken: refreshToken,
		DeviceInfo:   device,
		IPAddress:    ip,
		UserAgent:    ua,
		IsActive:     true,
		ExpiresAt:    time.Now().Add(s.jwt.RefreshExpiry()),
		LastSeenAt:   time.Now(),
	}
	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	// Update last login
	now := time.Now()
	user.LastLoginAt = &now
	user.LastLoginIP = &ip
	_ = s.users.Update(ctx, user)

	s.audit(ctx, &user.ID, "login", "user", ip, ua, "success", nil, 0)

	return &models.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.jwt.AccessExpiry().Seconds()),
		User:         user,
		SessionID:    sessionID,
	}, nil
}

func (s *Service) validatePasswordStrength(password string) error {
	cfg := &s.cfg.Security
	if len(password) < cfg.PasswordMinLength {
		return fmt.Errorf("password must be at least %d characters", cfg.PasswordMinLength)
	}
	var hasUpper, hasLower, hasDigit, hasSpec bool
	for _, c := range password {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasSpec = true
		}
	}
	if cfg.PasswordRequireUpper && !hasUpper {
		return fmt.Errorf("password must contain uppercase letter")
	}
	if cfg.PasswordRequireLower && !hasLower {
		return fmt.Errorf("password must contain lowercase letter")
	}
	if cfg.PasswordRequireDigit && !hasDigit {
		return fmt.Errorf("password must contain digit")
	}
	if cfg.PasswordRequireSpec && !hasSpec {
		return fmt.Errorf("password must contain special character")
	}
	return nil
}

func (s *Service) verifyBackupCode(user *models.User, code string) bool {
	hash := crypto.HashBackupCode(code)
	for i, h := range user.MFABackupCodes {
		if h == hash {
			// Remove used backup code
			user.MFABackupCodes = append(user.MFABackupCodes[:i], user.MFABackupCodes[i+1:]...)
			_ = s.users.Update(context.Background(), user)
			return true
		}
	}
	return false
}

func (s *Service) audit(ctx context.Context, userID *uuid.UUID, action, resource, ip, ua, status string, details map[string]interface{}, risk float32) {
	entry := &models.AuditLog{
		UserID:    userID,
		Action:    action,
		Resource:  resource,
		IPAddress: ip,
		UserAgent: ua,
		Status:    status,
		RiskScore: risk,
	}
	if details != nil {
		entry.Details = models.JSONB(details)
	}
	if err := s.audits.Log(ctx, entry); err != nil {
		s.log.Error("audit log failed", zap.Error(err))
	}
}

// ─── Errors ───────────────────────────────────────────────────────────────────

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrEmailAlreadyExists = errors.New("email already registered")
	ErrPhoneAlreadyExists = errors.New("phone already registered")
	ErrAccountLocked      = errors.New("account locked due to multiple failed attempts")
	ErrAccountSuspended   = errors.New("account suspended")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrSessionExpired     = errors.New("session expired")
	ErrSessionLimitReached = errors.New("session limit reached")
	ErrInvalidMFACode     = errors.New("invalid mfa code")
	ErrUserNotFound       = errors.New("user not found")
)
