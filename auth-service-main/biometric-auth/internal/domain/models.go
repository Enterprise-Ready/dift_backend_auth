package domain

import (
	"time"
)

// ─── User ────────────────────────────────────────────────────────────────────

type User struct {
	ID            string
	Phone         string
	Email         string
	PasswordHash  string
	TOTPSecret    string
	Status        UserStatus
	FailedAttempts int
	LockedUntil   *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusLocked   UserStatus = "locked"
	UserStatusDisabled UserStatus = "disabled"
)

// ─── Device ──────────────────────────────────────────────────────────────────

type Device struct {
	ID              string
	UserID          string
	Name            string
	Platform        Platform
	AppVersion      string
	OSVersion       string
	DeviceFingerprint string // hashed

	// Biometric
	BiometricEnabled  bool
	PublicKey         string // PEM encoded ECDSA/RSA public key
	KeyID             string // Secure Enclave / StrongBox key handle
	BiometricType     BiometricType
	EnrolledAt        *time.Time

	// Security
	AttestationData   string // Android SafetyNet / Apple DeviceCheck
	IsRooted          bool
	IsJailbroken      bool
	TrustScore        int // 0-100

	Status    DeviceStatus
	LastSeenAt time.Time
	CreatedAt  time.Time
	RevokedAt  *time.Time
	RevokedBy  string
}

type Platform string

const (
	PlatformAndroid Platform = "android"
	PlatformIOS     Platform = "ios"
)

type DeviceStatus string

const (
	DeviceStatusActive  DeviceStatus = "active"
	DeviceStatusRevoked DeviceStatus = "revoked"
	DeviceStatusBlocked DeviceStatus = "blocked"
)

type BiometricType string

const (
	BiometricFingerprint BiometricType = "fingerprint"
	BiometricFace        BiometricType = "face"
	BiometricIris        BiometricType = "iris"
)

// ─── Session / Token ─────────────────────────────────────────────────────────

type Session struct {
	ID           string
	UserID       string
	DeviceID     string
	RefreshToken string // hashed
	TokenFamily  string // for rotation lineage

	// Replay protection
	LastUsedAt   time.Time
	UseCount     int

	// Step-up
	StepUpToken    string
	StepUpExpiry   *time.Time

	Status    SessionStatus
	ExpiresAt time.Time
	CreatedAt time.Time
	IPAddress string
	UserAgent string
}

type SessionStatus string

const (
	SessionStatusActive   SessionStatus = "active"
	SessionStatusRevoked  SessionStatus = "revoked"
	SessionStatusExpired  SessionStatus = "expired"
	SessionStatusReplayed SessionStatus = "replayed" // detected replay attack
)

// ─── Biometric Challenge ─────────────────────────────────────────────────────

// Challenge is a server-generated nonce for biometric signing.
// Prevents replay by binding nonce + timestamp + deviceID + action.
type Challenge struct {
	ID        string
	Nonce     string // 32 bytes random, base64url
	UserID    string
	DeviceID  string
	Action    ChallengeAction
	HMAC      string    // HMAC-SHA256(nonce + deviceID + action + expiry, secret)
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

type ChallengeAction string

const (
	ChallengeActionEnroll      ChallengeAction = "enroll"
	ChallengeActionAuthenticate ChallengeAction = "authenticate"
	ChallengeActionStepUp      ChallengeAction = "step_up"
	ChallengeActionRevoke      ChallengeAction = "revoke"
)

// ─── Audit Log ───────────────────────────────────────────────────────────────

type AuditLog struct {
	ID        string
	UserID    string
	DeviceID  string
	SessionID string
	Action    AuditAction
	Result    AuditResult
	Details   map[string]any
	IPAddress string
	UserAgent string
	RiskScore int
	CreatedAt time.Time
}

type AuditAction string

const (
	AuditActionLogin              AuditAction = "login"
	AuditActionLoginFailed        AuditAction = "login_failed"
	AuditActionOTPVerify          AuditAction = "otp_verify"
	AuditActionBiometricEnroll    AuditAction = "biometric_enroll"
	AuditActionBiometricAuth      AuditAction = "biometric_auth"
	AuditActionBiometricFailed    AuditAction = "biometric_failed"
	AuditActionTokenRefresh       AuditAction = "token_refresh"
	AuditActionTokenRevoked       AuditAction = "token_revoked"
	AuditActionReplayDetected     AuditAction = "replay_detected"
	AuditActionDeviceRevoked      AuditAction = "device_revoked"
	AuditActionRootedDevice       AuditAction = "rooted_device_detected"
	AuditActionStepUpGranted      AuditAction = "step_up_granted"
	AuditActionStepUpFailed       AuditAction = "step_up_failed"
	AuditActionPaymentAuthorized  AuditAction = "payment_authorized"
	AuditActionLogout             AuditAction = "logout"
	AuditActionLogoutAll          AuditAction = "logout_all"
)

type AuditResult string

const (
	AuditResultSuccess AuditResult = "success"
	AuditResultFailure AuditResult = "failure"
	AuditResultBlocked AuditResult = "blocked"
)

// ─── Claims ──────────────────────────────────────────────────────────────────

type TokenClaims struct {
	UserID    string
	DeviceID  string
	SessionID string
	TokenType TokenType
	StepUp    bool
	StepUpExp *time.Time
}

type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)
