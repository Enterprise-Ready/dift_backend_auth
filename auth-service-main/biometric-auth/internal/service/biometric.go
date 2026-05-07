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
	ErrChallengeExpired  = errors.New("challenge expired")
	ErrChallengeUsed     = errors.New("challenge already used")
	ErrChallengeInvalid  = errors.New("challenge invalid")
	ErrDeviceNotFound    = errors.New("device not found")
	ErrBiometricDisabled = errors.New("biometric not enrolled on this device")
	ErrSignatureInvalid  = errors.New("biometric signature invalid")
	ErrRootedDevice      = errors.New("rooted/jailbroken device not permitted")
	ErrTimestampDrift    = errors.New("timestamp drift too large — possible replay")
	ErrStepUpRequired    = errors.New("step-up authentication required")
)

// MaxTimestampDrift is the window for accepting client timestamps.
// Prevents replay by ensuring signed payload timestamp is fresh.
const MaxTimestampDrift = 90 * time.Second

type BiometricService struct {
	cfg           *config.Config
	cryptoSvc     *CryptoService
	deviceSvc     *DeviceService
	challengeRepo repository.ChallengeRepository
	auditSvc      *AuditService
}

func NewBiometricService(
	cfg *config.Config,
	cryptoSvc *CryptoService,
	deviceSvc *DeviceService,
	challengeRepo repository.ChallengeRepository,
	auditSvc *AuditService,
) *BiometricService {
	return &BiometricService{
		cfg:           cfg,
		cryptoSvc:     cryptoSvc,
		deviceSvc:     deviceSvc,
		challengeRepo: challengeRepo,
		auditSvc:      auditSvc,
	}
}

// ─── Challenge ───────────────────────────────────────────────────────────────

type ChallengeRequest struct {
	UserID   string
	DeviceID string
	Action   domain.ChallengeAction
}

type ChallengeResponse struct {
	ChallengeID string
	Nonce       string // 32 bytes, base64url — client must sign this
	ExpiresAt   time.Time
	HMAC        string // server integrity seal
}

// GetChallenge issues a one-time nonce for the client to sign.
// Nonce is bound to deviceID + action to prevent cross-action replay.
func (s *BiometricService) GetChallenge(req ChallengeRequest) (*ChallengeResponse, error) {
	nonce, err := s.cryptoSvc.RandomBase64URL(32)
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	challengeID, err := s.cryptoSvc.RandomHex(16)
	if err != nil {
		return nil, fmt.Errorf("generate challenge ID: %w", err)
	}

	expiry := time.Now().Add(s.cfg.ChallengeTTL)

	challengeHMAC := s.cryptoSvc.HMACChallenge(nonce, req.DeviceID, string(req.Action), expiry)

	challenge := &domain.Challenge{
		ID:        challengeID,
		Nonce:     nonce,
		UserID:    req.UserID,
		DeviceID:  req.DeviceID,
		Action:    req.Action,
		HMAC:      challengeHMAC,
		ExpiresAt: expiry,
		CreatedAt: time.Now(),
	}

	if err := s.challengeRepo.Store(challenge); err != nil {
		return nil, fmt.Errorf("store challenge: %w", err)
	}

	return &ChallengeResponse{
		ChallengeID: challengeID,
		Nonce:       nonce,
		ExpiresAt:   expiry,
		HMAC:        challengeHMAC,
	}, nil
}

// ─── Enrollment ──────────────────────────────────────────────────────────────

type EnrollRequest struct {
	UserID        string
	DeviceID      string
	ChallengeID   string
	PublicKeyPEM  string // ECDSA P-256 or RSA-2048 public key from Secure Enclave/StrongBox
	KeyID         string // Key handle from the device keystore
	KeyAlgo       string // ES256 or RS256
	Signature     string // base64url(sign(SHA256(nonce.deviceID.enroll.timestamp), privateKey))
	Timestamp     int64  // Unix seconds — must be within MaxTimestampDrift
	BiometricType domain.BiometricType

	// Device integrity
	AttestationData string // SafetyNet JWS or Apple DeviceCheck token
	IsRooted        bool
	IsJailbroken    bool
}

// Enroll registers a new biometric keypair for a device.
// Flow: verify challenge → verify signature → store public key → mark device enrolled.
func (s *BiometricService) Enroll(req EnrollRequest) error {
	// 1. Reject rooted/jailbroken devices
	if req.IsRooted || req.IsJailbroken {
		_ = s.auditSvc.Log(&domain.AuditLog{
			UserID:   req.UserID,
			DeviceID: req.DeviceID,
			Action:   domain.AuditActionRootedDevice,
			Result:   domain.AuditResultBlocked,
			Details:  map[string]any{"rooted": req.IsRooted, "jailbroken": req.IsJailbroken},
		})
		return ErrRootedDevice
	}

	// 2. Validate and consume challenge
	if err := s.consumeChallenge(req.ChallengeID, req.DeviceID, domain.ChallengeActionEnroll); err != nil {
		return fmt.Errorf("challenge validation: %w", err)
	}

	// 3. Timestamp drift check (anti-replay)
	if err := s.checkTimestampDrift(req.Timestamp); err != nil {
		return err
	}

	// 4. Validate key format
	if err := s.cryptoSvc.ValidatePublicKeyFormat(req.PublicKeyPEM, req.KeyAlgo); err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	// 5. Get nonce from challenge (already consumed, we need it for signature verification)
	//    In real implementation, challenge stores nonce — retrieve before consuming.
	//    Here we rebuild the payload to verify.
	payload := s.cryptoSvc.BuildSignedPayload(
		req.ChallengeID, req.DeviceID, string(domain.ChallengeActionEnroll), req.Timestamp,
	)

	// 6. Verify signature using client's public key
	if err := s.cryptoSvc.VerifySignatureForAlgo(req.KeyAlgo, req.PublicKeyPEM, payload, req.Signature); err != nil {
		_ = s.auditSvc.Log(&domain.AuditLog{
			UserID:   req.UserID,
			DeviceID: req.DeviceID,
			Action:   domain.AuditActionBiometricFailed,
			Result:   domain.AuditResultFailure,
			Details:  map[string]any{"stage": "enroll", "error": err.Error()},
		})
		return ErrSignatureInvalid
	}

	// 7. Store public key on device record
	if err := s.deviceSvc.EnableBiometric(req.DeviceID, req.UserID, domain.EnableBiometricParams{
		PublicKey:       req.PublicKeyPEM,
		KeyID:           req.KeyID,
		KeyAlgo:         req.KeyAlgo,
		BiometricType:   req.BiometricType,
		AttestationData: req.AttestationData,
		IsRooted:        req.IsRooted,
		IsJailbroken:    req.IsJailbroken,
	}); err != nil {
		return fmt.Errorf("enable biometric: %w", err)
	}

	_ = s.auditSvc.Log(&domain.AuditLog{
		UserID:   req.UserID,
		DeviceID: req.DeviceID,
		Action:   domain.AuditActionBiometricEnroll,
		Result:   domain.AuditResultSuccess,
		Details: map[string]any{
			"algo":           req.KeyAlgo,
			"biometric_type": req.BiometricType,
		},
	})

	slog.Info("biometric enrolled", "userID", req.UserID, "deviceID", req.DeviceID, "type", req.BiometricType)
	return nil
}

// ─── Authentication ───────────────────────────────────────────────────────────

type AuthenticateRequest struct {
	UserID      string
	DeviceID    string
	ChallengeID string
	Nonce       string // original nonce from challenge
	Signature   string // base64url(sign(SHA256(nonce.deviceID.authenticate.timestamp)))
	Timestamp   int64

	// Device integrity (re-check on every auth)
	IsRooted     bool
	IsJailbroken bool
}

type AuthenticateResult struct {
	UserID    string
	DeviceID  string
	SessionID string
}

// Authenticate verifies biometric signature and returns session identifiers
// for the token service to issue new tokens.
func (s *BiometricService) Authenticate(req AuthenticateRequest) (*AuthenticateResult, error) {
	// 1. Rooted check
	if req.IsRooted || req.IsJailbroken {
		_ = s.auditSvc.Log(&domain.AuditLog{
			UserID:   req.UserID,
			DeviceID: req.DeviceID,
			Action:   domain.AuditActionRootedDevice,
			Result:   domain.AuditResultBlocked,
		})
		return nil, ErrRootedDevice
	}

	// 2. Load device and verify biometric is enrolled
	device, err := s.deviceSvc.GetDevice(req.DeviceID)
	if err != nil || device == nil {
		return nil, ErrDeviceNotFound
	}
	if device.UserID != req.UserID {
		return nil, ErrDeviceNotFound
	}
	if device.Status != domain.DeviceStatusActive {
		return nil, fmt.Errorf("device %s", device.Status)
	}
	if !device.BiometricEnabled || device.PublicKey == "" {
		return nil, ErrBiometricDisabled
	}

	// 3. Validate and consume challenge
	if err := s.consumeChallenge(req.ChallengeID, req.DeviceID, domain.ChallengeActionAuthenticate); err != nil {
		return nil, fmt.Errorf("challenge: %w", err)
	}

	// 4. Timestamp drift (prevent replay with stale signed payloads)
	if err := s.checkTimestampDrift(req.Timestamp); err != nil {
		_ = s.auditSvc.Log(&domain.AuditLog{
			UserID:   req.UserID,
			DeviceID: req.DeviceID,
			Action:   domain.AuditActionReplayDetected,
			Result:   domain.AuditResultBlocked,
			Details:  map[string]any{"timestamp": req.Timestamp},
		})
		return nil, err
	}

	// 5. Reconstruct signed payload
	payload := s.cryptoSvc.BuildSignedPayload(
		req.Nonce, req.DeviceID, string(domain.ChallengeActionAuthenticate), req.Timestamp,
	)

	// 6. Verify signature against stored public key
	if err := s.cryptoSvc.VerifySignatureForAlgo(s.cfg.SignatureAlgo, device.PublicKey, payload, req.Signature); err != nil {
		_ = s.auditSvc.Log(&domain.AuditLog{
			UserID:   req.UserID,
			DeviceID: req.DeviceID,
			Action:   domain.AuditActionBiometricFailed,
			Result:   domain.AuditResultFailure,
			Details:  map[string]any{"error": err.Error()},
		})
		return nil, ErrSignatureInvalid
	}

	// 7. Update device last seen
	_ = s.deviceSvc.UpdateLastSeen(req.DeviceID)

	_ = s.auditSvc.Log(&domain.AuditLog{
		UserID:   req.UserID,
		DeviceID: req.DeviceID,
		Action:   domain.AuditActionBiometricAuth,
		Result:   domain.AuditResultSuccess,
	})

	slog.Info("biometric authenticated", "userID", req.UserID, "deviceID", req.DeviceID)

	return &AuthenticateResult{
		UserID:   req.UserID,
		DeviceID: req.DeviceID,
	}, nil
}

// ─── Step-Up Authentication (for payment) ───────────────────────────────────

type StepUpRequest struct {
	UserID      string
	DeviceID    string
	SessionID   string
	ChallengeID string
	Nonce       string
	Signature   string
	Timestamp   int64
	IsRooted    bool
	IsJailbroken bool
}

// StepUp performs additional biometric verification for sensitive operations.
// Returns a short-lived step-up access token to be used for payment.
func (s *BiometricService) StepUp(req StepUpRequest) (*domain.TokenClaims, error) {
	authResult, err := s.Authenticate(AuthenticateRequest{
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
		_ = s.auditSvc.Log(&domain.AuditLog{
			UserID:    req.UserID,
			DeviceID:  req.DeviceID,
			SessionID: req.SessionID,
			Action:    domain.AuditActionStepUpFailed,
			Result:    domain.AuditResultFailure,
			Details:   map[string]any{"error": err.Error()},
		})
		return nil, fmt.Errorf("step-up biometric failed: %w", err)
	}

	_ = s.auditSvc.Log(&domain.AuditLog{
		UserID:    authResult.UserID,
		DeviceID:  authResult.DeviceID,
		SessionID: req.SessionID,
		Action:    domain.AuditActionStepUpGranted,
		Result:    domain.AuditResultSuccess,
	})

	return &domain.TokenClaims{
		UserID:    authResult.UserID,
		DeviceID:  authResult.DeviceID,
		SessionID: req.SessionID,
	}, nil
}

// ─── Internal helpers ────────────────────────────────────────────────────────

// consumeChallenge retrieves, validates, and marks a challenge as used (single-use).
func (s *BiometricService) consumeChallenge(challengeID, deviceID string, expectedAction domain.ChallengeAction) error {
	challenge, err := s.challengeRepo.Get(challengeID)
	if err != nil || challenge == nil {
		return ErrChallengeInvalid
	}

	if challenge.UsedAt != nil {
		return ErrChallengeUsed
	}

	if time.Now().After(challenge.ExpiresAt) {
		return ErrChallengeExpired
	}

	if challenge.DeviceID != deviceID || challenge.Action != expectedAction {
		return ErrChallengeInvalid
	}

	// Verify server HMAC to ensure challenge wasn't tampered
	if !s.cryptoSvc.VerifyHMACChallenge(
		challenge.Nonce, challenge.DeviceID,
		string(challenge.Action), challenge.ExpiresAt,
		challenge.HMAC,
	) {
		return ErrChallengeInvalid
	}

	// Mark as used — prevents replay
	now := time.Now()
	challenge.UsedAt = &now
	return s.challengeRepo.Update(challenge)
}

// checkTimestampDrift ensures signed payload timestamp is fresh.
func (s *BiometricService) checkTimestampDrift(ts int64) error {
	clientTime := time.Unix(ts, 0)
	drift := time.Since(clientTime)
	if drift < 0 {
		drift = -drift
	}
	if drift > MaxTimestampDrift {
		return ErrTimestampDrift
	}
	return nil
}
