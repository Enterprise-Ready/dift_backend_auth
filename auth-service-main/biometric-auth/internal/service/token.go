package service

import (
	cryptoRand "crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"biometric-auth/internal/config"
	"biometric-auth/internal/domain"
	"biometric-auth/internal/repository"
)

var (
	ErrTokenExpired      = errors.New("token expired")
	ErrTokenInvalid      = errors.New("token invalid")
	ErrTokenRevoked      = errors.New("token revoked")
	ErrReplayDetected    = errors.New("replay attack detected")
	ErrFamilyCompromised = errors.New("token family compromised — all sessions revoked")
)

// TokenService manages HMAC-signed tokens with rotation and replay protection.
type TokenService struct {
	cfg         *config.Config
	sessionRepo repository.SessionRepository
}

func NewTokenService(cfg *config.Config, sessionRepo repository.SessionRepository) *TokenService {
	return &TokenService{cfg: cfg, sessionRepo: sessionRepo}
}

type tokenPayload struct {
	Sub       string `json:"sub"`
	DeviceID  string `json:"did"`
	SessionID string `json:"sid"`
	Type      string `json:"typ"`
	Family    string `json:"fam"`
	StepUp    bool   `json:"sup,omitempty"`
	StepUpExp *int64 `json:"sup_exp,omitempty"`
	Iat       int64  `json:"iat"`
	Exp       int64  `json:"exp"`
	Jti       string `json:"jti"`
}

func (s *TokenService) IssueTokenPair(userID, deviceID, sessionID, family string) (accessToken, refreshToken string, err error) {
	now := time.Now()

	jtiAccess, err := secureHex(16)
	if err != nil {
		return "", "", err
	}
	jtiRefresh, err := secureHex(16)
	if err != nil {
		return "", "", err
	}

	accessPayload := tokenPayload{
		Sub: userID, DeviceID: deviceID, SessionID: sessionID,
		Type: string(domain.TokenTypeAccess), Family: family,
		Iat: now.Unix(), Exp: now.Add(s.cfg.AccessTokenTTL).Unix(), Jti: jtiAccess,
	}
	refreshPayload := tokenPayload{
		Sub: userID, DeviceID: deviceID, SessionID: sessionID,
		Type: string(domain.TokenTypeRefresh), Family: family,
		Iat: now.Unix(), Exp: now.Add(s.cfg.RefreshTokenTTL).Unix(), Jti: jtiRefresh,
	}

	accessToken, err = s.sign(accessPayload, s.cfg.AccessTokenSecret)
	if err != nil {
		return "", "", fmt.Errorf("sign access token: %w", err)
	}
	refreshToken, err = s.sign(refreshPayload, s.cfg.RefreshTokenSecret)
	if err != nil {
		return "", "", fmt.Errorf("sign refresh token: %w", err)
	}
	return accessToken, refreshToken, nil
}

func (s *TokenService) IssueStepUpToken(claims *domain.TokenClaims) (string, error) {
	now := time.Now()
	exp := now.Add(s.cfg.StepUpTokenTTL)
	expUnix := exp.Unix()
	jti, err := secureHex(16)
	if err != nil {
		return "", err
	}
	payload := tokenPayload{
		Sub: claims.UserID, DeviceID: claims.DeviceID, SessionID: claims.SessionID,
		Type: string(domain.TokenTypeAccess), StepUp: true, StepUpExp: &expUnix,
		Iat: now.Unix(), Exp: now.Add(s.cfg.AccessTokenTTL).Unix(), Jti: jti,
	}
	return s.sign(payload, s.cfg.AccessTokenSecret)
}

// RotateRefreshToken — single-use token rotation.
// If old token is replayed → entire family is revoked.
func (s *TokenService) RotateRefreshToken(rawRefreshToken, deviceID string) (newAccess, newRefresh string, err error) {
	payload, err := s.verify(rawRefreshToken, s.cfg.RefreshTokenSecret)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	if payload.Type != string(domain.TokenTypeRefresh) {
		return "", "", ErrTokenInvalid
	}
	if !hmacEqual(payload.DeviceID, deviceID) {
		return "", "", errors.New("device mismatch")
	}

	session, err := s.sessionRepo.GetByID(payload.SessionID)
	if err != nil || session == nil {
		return "", "", ErrTokenRevoked
	}
	if session.Status != domain.SessionStatusActive {
		return "", "", ErrTokenRevoked
	}

	incomingHash := hashRefreshToken(rawRefreshToken)
	if !hmacEqual(incomingHash, session.RefreshToken) {
		// ⚠️ REPLAY: old token reused after rotation — revoke family
		_ = s.sessionRepo.RevokeFamily(payload.Family, domain.SessionStatusReplayed)
		return "", "", ErrFamilyCompromised
	}

	newAccess, newRefresh, err = s.IssueTokenPair(payload.Sub, payload.DeviceID, payload.SessionID, payload.Family)
	if err != nil {
		return "", "", err
	}

	session.RefreshToken = hashRefreshToken(newRefresh)
	session.LastUsedAt = time.Now()
	session.UseCount++
	if err := s.sessionRepo.Update(session); err != nil {
		return "", "", fmt.Errorf("update session: %w", err)
	}
	return newAccess, newRefresh, nil
}

func (s *TokenService) VerifyAccessToken(raw string) (*domain.TokenClaims, error) {
	payload, err := s.verify(raw, s.cfg.AccessTokenSecret)
	if err != nil {
		return nil, err
	}
	if payload.Type != string(domain.TokenTypeAccess) {
		return nil, ErrTokenInvalid
	}

	var stepUpExp *time.Time
	if payload.StepUpExp != nil {
		t := time.Unix(*payload.StepUpExp, 0)
		stepUpExp = &t
	}
	return &domain.TokenClaims{
		UserID:    payload.Sub,
		DeviceID:  payload.DeviceID,
		SessionID: payload.SessionID,
		TokenType: domain.TokenTypeAccess,
		StepUp:    payload.StepUp,
		StepUpExp: stepUpExp,
	}, nil
}

func (s *TokenService) RevokeSession(sessionID string) error {
	session, err := s.sessionRepo.GetByID(sessionID)
	if err != nil {
		return err
	}
	session.Status = domain.SessionStatusRevoked
	return s.sessionRepo.Update(session)
}

func (s *TokenService) RevokeAllUserSessions(userID string) error {
	return s.sessionRepo.RevokeAllByUser(userID)
}

func (s *TokenService) sign(payload tokenPayload, secret string) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := header + "." + payloadB64
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig, nil
}

func (s *TokenService) verify(token, secret string) (*tokenPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrTokenInvalid
	}
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)

	gotSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrTokenInvalid
	}
	if !hmac.Equal(gotSig, expectedSig) {
		return nil, ErrTokenInvalid
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrTokenInvalid
	}
	var p tokenPayload
	if err := json.Unmarshal(payloadJSON, &p); err != nil {
		return nil, ErrTokenInvalid
	}
	if time.Now().Unix() > p.Exp {
		return nil, ErrTokenExpired
	}
	return &p, nil
}

func hashRefreshToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func hmacEqual(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

func secureHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := cryptoRand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
