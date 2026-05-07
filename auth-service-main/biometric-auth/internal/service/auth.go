package service

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"biometric-auth/internal/config"
	"biometric-auth/internal/domain"
	"biometric-auth/internal/repository"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked      = errors.New("account locked — too many failed attempts")
	ErrAccountDisabled    = errors.New("account disabled")
	ErrOTPInvalid         = errors.New("OTP invalid or expired")
)

type AuthService struct {
	cfg          *config.Config
	userRepo     repository.UserRepository
	tokenSvc     *TokenService
	deviceSvc    *DeviceService
	biometricSvc *BiometricService
	auditSvc     *AuditService
}

func NewAuthService(
	cfg *config.Config,
	userRepo repository.UserRepository,
	tokenSvc *TokenService,
	deviceSvc *DeviceService,
	biometricSvc *BiometricService,
	auditSvc *AuditService,
) *AuthService {
	return &AuthService{
		cfg:          cfg,
		userRepo:     userRepo,
		tokenSvc:     tokenSvc,
		deviceSvc:    deviceSvc,
		biometricSvc: biometricSvc,
		auditSvc:     auditSvc,
	}
}

// ─── Primary Login ───────────────────────────────────────────────────────────

type LoginRequest struct {
	Identifier string // phone or email
	Password   string
	DeviceID   string
	IPAddress  string
	UserAgent  string
	// Device info for registration/update
	DeviceName  string
	Platform    domain.Platform
	AppVersion  string
	OSVersion   string
	Fingerprint string
	IsRooted    bool
	IsJailbroken bool
}

type LoginResponse struct {
	AccessToken  string
	RefreshToken string
	UserID       string
	RequiresOTP  bool // if 2FA is enabled, send OTP next
}

// Login authenticates with password, creates session and issues tokens.
func (s *AuthService) Login(req LoginRequest) (*LoginResponse, error) {
	user, err := s.userRepo.FindByIdentifier(req.Identifier)
	if err != nil || user == nil {
		// Constant-time fake hash comparison to prevent timing attacks
		_, _ = fakeCryptoSvc.VerifyPassword(req.Password, dummyHash)
		_ = s.auditSvc.Log(&domain.AuditLog{
			Action: domain.AuditActionLoginFailed,
			Result: domain.AuditResultFailure,
			Details: map[string]any{"identifier": req.Identifier, "reason": "user not found"},
			IPAddress: req.IPAddress,
		})
		return nil, ErrInvalidCredentials
	}

	// Check account status
	if user.Status == domain.UserStatusDisabled {
		return nil, ErrAccountDisabled
	}

	// Lockout check
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return nil, ErrAccountLocked
	}

	// Verify password
	ok, err := fakeCryptoSvc.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !ok {
		s.handleFailedLogin(user, req.IPAddress)
		return nil, ErrInvalidCredentials
	}

	// Reset failed attempts on success
	user.FailedAttempts = 0
	user.LockedUntil = nil
	_ = s.userRepo.Update(user)

	// Register/update device
	device := &domain.Device{
		ID:                req.DeviceID,
		Name:              req.DeviceName,
		Platform:          req.Platform,
		AppVersion:        req.AppVersion,
		OSVersion:         req.OSVersion,
		DeviceFingerprint: req.Fingerprint,
		IsRooted:          req.IsRooted,
		IsJailbroken:      req.IsJailbroken,
	}
	if _, err := s.deviceSvc.RegisterDevice(user.ID, device); err != nil {
		slog.Warn("device registration failed", "error", err)
	}

	// Create session
	session, err := s.createSession(user.ID, req.DeviceID, req.IPAddress, req.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	_ = s.auditSvc.Log(&domain.AuditLog{
		UserID:    user.ID,
		DeviceID:  req.DeviceID,
		SessionID: session.ID,
		Action:    domain.AuditActionLogin,
		Result:    domain.AuditResultSuccess,
		IPAddress: req.IPAddress,
		UserAgent: req.UserAgent,
	})

	slog.Info("user logged in", "userID", user.ID, "deviceID", req.DeviceID)

	return &LoginResponse{
		AccessToken:  session.accessToken,
		RefreshToken: session.refreshToken,
		UserID:       user.ID,
		RequiresOTP:  user.TOTPSecret != "",
	}, nil
}

// ─── OTP (TOTP / SMS) ────────────────────────────────────────────────────────

type OTPVerifyRequest struct {
	UserID    string
	OTP       string
	SessionID string
	IPAddress string
}

// VerifyOTP validates TOTP or SMS OTP as second factor.
func (s *AuthService) VerifyOTP(req OTPVerifyRequest) error {
	user, err := s.userRepo.FindByID(req.UserID)
	if err != nil || user == nil {
		return ErrInvalidCredentials
	}

	// In production: validate TOTP using golang.org/x/crypto/otp or gotp
	// totp.Validate(req.OTP, user.TOTPSecret) with time window ±1
	valid := validateTOTP(req.OTP, user.TOTPSecret)
	if !valid {
		_ = s.auditSvc.Log(&domain.AuditLog{
			UserID:    req.UserID,
			SessionID: req.SessionID,
			Action:    domain.AuditActionOTPVerify,
			Result:    domain.AuditResultFailure,
			IPAddress: req.IPAddress,
		})
		return ErrOTPInvalid
	}

	_ = s.auditSvc.Log(&domain.AuditLog{
		UserID:    req.UserID,
		SessionID: req.SessionID,
		Action:    domain.AuditActionOTPVerify,
		Result:    domain.AuditResultSuccess,
		IPAddress: req.IPAddress,
	})
	return nil
}

// ─── Biometric Token Exchange ─────────────────────────────────────────────────

type BiometricTokenRequest struct {
	UserID      string
	DeviceID    string
	ChallengeID string
	Nonce       string
	Signature   string
	Timestamp   int64
	SessionID   string // existing session to refresh
	IsRooted    bool
	IsJailbroken bool
}

type BiometricTokenResponse struct {
	AccessToken  string
	RefreshToken string
}

// ExchangeBiometricToken verifies biometric and issues fresh token pair.
// This is called after the mobile app completes fingerprint/face scan.
func (s *AuthService) ExchangeBiometricToken(req BiometricTokenRequest) (*BiometricTokenResponse, error) {
	_, err := s.biometricSvc.Authenticate(AuthenticateRequest{
		UserID:       req.UserID,
		DeviceID:     req.DeviceID,
		ChallengeID:  req.ChallengeID,
		Nonce:        req.Nonce,
		Signature:    req.Signature,
		Timestamp:    req.Timestamp,
		IsRooted:     req.IsRooted,
		IsJailbroken: req.IsJailbroken,
	})
	if err != nil {
		return nil, err
	}

	// Rotate session tokens
	session, err := s.sessionRepo().GetByID(req.SessionID)
	if err != nil || session == nil {
		return nil, ErrTokenRevoked
	}

	accessToken, refreshToken, err := s.tokenSvc.IssueTokenPair(
		req.UserID, req.DeviceID, req.SessionID, session.TokenFamily,
	)
	if err != nil {
		return nil, err
	}

	session.RefreshToken = hashRefreshToken(refreshToken)
	session.LastUsedAt = time.Now()
	session.UseCount++
	_ = s.sessionRepo().Update(session)

	return &BiometricTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// ─── Refresh ─────────────────────────────────────────────────────────────────

type RefreshRequest struct {
	RefreshToken string
	DeviceID     string
	IPAddress    string
}

type RefreshResponse struct {
	AccessToken  string
	RefreshToken string
}

func (s *AuthService) RefreshToken(req RefreshRequest) (*RefreshResponse, error) {
	newAccess, newRefresh, err := s.tokenSvc.RotateRefreshToken(req.RefreshToken, req.DeviceID)
	if err != nil {
		_ = s.auditSvc.Log(&domain.AuditLog{
			Action:    domain.AuditActionTokenRevoked,
			Result:    domain.AuditResultFailure,
			IPAddress: req.IPAddress,
			Details:   map[string]any{"error": err.Error()},
		})
		return nil, err
	}

	return &RefreshResponse{
		AccessToken:  newAccess,
		RefreshToken: newRefresh,
	}, nil
}

// ─── Logout ──────────────────────────────────────────────────────────────────

func (s *AuthService) Logout(claims *domain.TokenClaims) error {
	_ = s.auditSvc.Log(&domain.AuditLog{
		UserID:    claims.UserID,
		DeviceID:  claims.DeviceID,
		SessionID: claims.SessionID,
		Action:    domain.AuditActionLogout,
		Result:    domain.AuditResultSuccess,
	})
	return s.tokenSvc.RevokeSession(claims.SessionID)
}

func (s *AuthService) LogoutAll(claims *domain.TokenClaims) error {
	_ = s.auditSvc.Log(&domain.AuditLog{
		UserID:   claims.UserID,
		DeviceID: claims.DeviceID,
		Action:   domain.AuditActionLogoutAll,
		Result:   domain.AuditResultSuccess,
	})
	return s.tokenSvc.RevokeAllUserSessions(claims.UserID)
}

// ─── Step-Up for Payment ──────────────────────────────────────────────────────

type StepUpAuthRequest struct {
	Claims      *domain.TokenClaims
	ChallengeID string
	Nonce       string
	Signature   string
	Timestamp   int64
	IsRooted    bool
	IsJailbroken bool
}

func (s *AuthService) AuthorizePayment(req StepUpAuthRequest) (string, error) {
	stepUpClaims, err := s.biometricSvc.StepUp(StepUpRequest{
		UserID:       req.Claims.UserID,
		DeviceID:     req.Claims.DeviceID,
		SessionID:    req.Claims.SessionID,
		ChallengeID:  req.ChallengeID,
		Nonce:        req.Nonce,
		Signature:    req.Signature,
		Timestamp:    req.Timestamp,
		IsRooted:     req.IsRooted,
		IsJailbroken: req.IsJailbroken,
	})
	if err != nil {
		return "", err
	}

	stepUpToken, err := s.tokenSvc.IssueStepUpToken(stepUpClaims)
	if err != nil {
		return "", err
	}

	_ = s.auditSvc.Log(&domain.AuditLog{
		UserID:    stepUpClaims.UserID,
		DeviceID:  stepUpClaims.DeviceID,
		SessionID: stepUpClaims.SessionID,
		Action:    domain.AuditActionPaymentAuthorized,
		Result:    domain.AuditResultSuccess,
	})

	return stepUpToken, nil
}

// ─── Internal helpers ────────────────────────────────────────────────────────

type sessionResult struct {
	ID           string
	accessToken  string
	refreshToken string
	TokenFamily  string
}

func (s *AuthService) createSession(userID, deviceID, ip, ua string) (*sessionResult, error) {
	sessionID, err := secureHex(16)
	if err != nil {
		return nil, err
	}
	family, err := secureHex(16)
	if err != nil {
		return nil, err
	}

	accessToken, refreshToken, err := s.tokenSvc.IssueTokenPair(userID, deviceID, sessionID, family)
	if err != nil {
		return nil, err
	}

	session := &domain.Session{
		ID:           sessionID,
		UserID:       userID,
		DeviceID:     deviceID,
		RefreshToken: hashRefreshToken(refreshToken),
		TokenFamily:  family,
		Status:       domain.SessionStatusActive,
		ExpiresAt:    time.Now().Add(s.cfg.RefreshTokenTTL),
		CreatedAt:    time.Now(),
		LastUsedAt:   time.Now(),
		IPAddress:    ip,
		UserAgent:    ua,
	}

	if err := s.sessionRepo().Store(session); err != nil {
		return nil, fmt.Errorf("store session: %w", err)
	}

	return &sessionResult{
		ID:           sessionID,
		accessToken:  accessToken,
		refreshToken: refreshToken,
		TokenFamily:  family,
	}, nil
}

func (s *AuthService) handleFailedLogin(user *domain.User, ip string) {
	user.FailedAttempts++
	if user.FailedAttempts >= s.cfg.MaxLoginAttempts {
		lockUntil := time.Now().Add(s.cfg.LockoutDuration)
		user.LockedUntil = &lockUntil
		user.Status = domain.UserStatusLocked
	}
	_ = s.userRepo.Update(user)
	_ = s.auditSvc.Log(&domain.AuditLog{
		UserID:    user.ID,
		Action:    domain.AuditActionLoginFailed,
		Result:    domain.AuditResultFailure,
		IPAddress: ip,
		Details: map[string]any{
			"attempts": user.FailedAttempts,
			"locked":   user.LockedUntil != nil,
		},
		RiskScore: user.FailedAttempts * 20,
	})
}

// sessionRepo returns the session repository — in real code inject directly.
func (s *AuthService) sessionRepo() repository.SessionRepository {
	return s.tokenSvc.sessionRepo
}

// fakeCryptoSvc is used for constant-time operations on missing users.
var fakeCryptoSvc = &CryptoService{}

// dummyHash is a valid argon2 hash used for constant-time verification on unknown users.
const dummyHash = "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"

// validateTOTP is a placeholder — use github.com/pquerna/otp in production.
func validateTOTP(otp, secret string) bool {
	// Implementation: use TOTP library with ±1 time step tolerance
	// totp.ValidateCustom(otp, secret, time.Now(), totp.ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	_ = otp
	_ = secret
	return true // placeholder
}
