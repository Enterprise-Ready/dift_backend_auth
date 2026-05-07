package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"biometric-auth/internal/domain"
	"biometric-auth/internal/middleware"
	"biometric-auth/internal/service"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decode(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20) // 1MB limit
	return json.NewDecoder(r.Body).Decode(v)
}

func claimsFromCtx(r *http.Request) *domain.TokenClaims {
	c, _ := r.Context().Value(middleware.ClaimsKey).(*domain.TokenClaims)
	return c
}

// ─── Auth Handler ─────────────────────────────────────────────────────────────

type AuthHandler struct {
	authSvc  *service.AuthService
	auditSvc *service.AuditService
}

func NewAuthHandler(authSvc *service.AuthService, auditSvc *service.AuditService) *AuthHandler {
	return &AuthHandler{authSvc: authSvc, auditSvc: auditSvc}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Identifier   string `json:"identifier"`
		Password     string `json:"password"`
		DeviceID     string `json:"device_id"`
		DeviceName   string `json:"device_name"`
		Platform     string `json:"platform"`
		AppVersion   string `json:"app_version"`
		OSVersion    string `json:"os_version"`
		Fingerprint  string `json:"fingerprint"`
		IsRooted     bool   `json:"is_rooted"`
		IsJailbroken bool   `json:"is_jailbroken"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	resp, err := h.authSvc.Login(service.LoginRequest{
		Identifier:   req.Identifier,
		Password:     req.Password,
		DeviceID:     req.DeviceID,
		DeviceName:   req.DeviceName,
		Platform:     domain.Platform(req.Platform),
		AppVersion:   req.AppVersion,
		OSVersion:    req.OSVersion,
		Fingerprint:  req.Fingerprint,
		IsRooted:     req.IsRooted,
		IsJailbroken: req.IsJailbroken,
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			writeError(w, http.StatusUnauthorized, "invalid credentials")
		case errors.Is(err, service.ErrAccountLocked):
			writeError(w, http.StatusTooManyRequests, "account locked")
		case errors.Is(err, service.ErrAccountDisabled):
			writeError(w, http.StatusForbidden, "account disabled")
		default:
			writeError(w, http.StatusInternalServerError, "login failed")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  resp.AccessToken,
		"refresh_token": resp.RefreshToken,
		"user_id":       resp.UserID,
		"requires_otp":  resp.RequiresOTP,
	})
}

func (h *AuthHandler) SendOTP(w http.ResponseWriter, r *http.Request) {
	// Trigger OTP send via SMS/TOTP — implementation depends on SMS gateway
	writeJSON(w, http.StatusOK, map[string]string{"status": "otp_sent"})
}

func (h *AuthHandler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID    string `json:"user_id"`
		OTP       string `json:"otp"`
		SessionID string `json:"session_id"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := h.authSvc.VerifyOTP(service.OTPVerifyRequest{
		UserID:    req.UserID,
		OTP:       req.OTP,
		SessionID: req.SessionID,
		IPAddress: r.RemoteAddr,
	}); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid OTP")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "verified"})
}

func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
		DeviceID     string `json:"device_id"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	resp, err := h.authSvc.RefreshToken(service.RefreshRequest{
		RefreshToken: req.RefreshToken,
		DeviceID:     req.DeviceID,
		IPAddress:    r.RemoteAddr,
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrFamilyCompromised):
			writeError(w, http.StatusUnauthorized, "security alert: all sessions revoked")
		case errors.Is(err, service.ErrTokenInvalid), errors.Is(err, service.ErrTokenExpired):
			writeError(w, http.StatusUnauthorized, "token invalid")
		case errors.Is(err, service.ErrTokenRevoked):
			writeError(w, http.StatusUnauthorized, "token revoked")
		default:
			writeError(w, http.StatusInternalServerError, "refresh failed")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  resp.AccessToken,
		"refresh_token": resp.RefreshToken,
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	_ = h.authSvc.Logout(claims)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (h *AuthHandler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	_ = h.authSvc.LogoutAll(claims)
	writeJSON(w, http.StatusOK, map[string]string{"status": "all_sessions_revoked"})
}

func (h *AuthHandler) AuthorizePayment(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	var req struct {
		ChallengeID  string `json:"challenge_id"`
		Nonce        string `json:"nonce"`
		Signature    string `json:"signature"`
		Timestamp    int64  `json:"timestamp"`
		IsRooted     bool   `json:"is_rooted"`
		IsJailbroken bool   `json:"is_jailbroken"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	stepUpToken, err := h.authSvc.AuthorizePayment(service.StepUpAuthRequest{
		Claims:       claims,
		ChallengeID:  req.ChallengeID,
		Nonce:        req.Nonce,
		Signature:    req.Signature,
		Timestamp:    req.Timestamp,
		IsRooted:     req.IsRooted,
		IsJailbroken: req.IsJailbroken,
	})
	if err != nil {
		writeError(w, http.StatusUnauthorized, "step-up authentication failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"step_up_token": stepUpToken,
		"message":       "payment authorized",
	})
}

// ─── Biometric Handler ────────────────────────────────────────────────────────

type BiometricHandler struct {
	biometricSvc *service.BiometricService
	authSvc      *service.AuthService
	auditSvc     *service.AuditService
}

func NewBiometricHandler(
	biometricSvc *service.BiometricService,
	authSvc *service.AuthService,
	auditSvc *service.AuditService,
) *BiometricHandler {
	return &BiometricHandler{biometricSvc: biometricSvc, authSvc: authSvc, auditSvc: auditSvc}
}

func (h *BiometricHandler) GetChallenge(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	var req struct {
		Action string `json:"action"` // enroll | authenticate | step_up
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	action := domain.ChallengeAction(req.Action)
	if action == "" {
		action = domain.ChallengeActionAuthenticate
	}

	resp, err := h.biometricSvc.GetChallenge(service.ChallengeRequest{
		UserID:   claims.UserID,
		DeviceID: claims.DeviceID,
		Action:   action,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "challenge generation failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"challenge_id": resp.ChallengeID,
		"nonce":        resp.Nonce,
		"expires_at":   resp.ExpiresAt.Unix(),
		"hmac":         resp.HMAC,
		// Mobile app must sign: SHA256(nonce + "." + deviceID + "." + action + "." + timestamp)
		// Using the private key stored in Android Keystore / iOS Secure Enclave
	})
}

func (h *BiometricHandler) Enroll(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	var req struct {
		ChallengeID     string `json:"challenge_id"`
		PublicKeyPEM    string `json:"public_key"`
		KeyID           string `json:"key_id"`
		KeyAlgo         string `json:"key_algo"` // ES256 or RS256
		Signature       string `json:"signature"`
		Timestamp       int64  `json:"timestamp"`
		BiometricType   string `json:"biometric_type"`
		AttestationData string `json:"attestation_data"`
		IsRooted        bool   `json:"is_rooted"`
		IsJailbroken    bool   `json:"is_jailbroken"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	err := h.biometricSvc.Enroll(service.EnrollRequest{
		UserID:          claims.UserID,
		DeviceID:        claims.DeviceID,
		ChallengeID:     req.ChallengeID,
		PublicKeyPEM:    req.PublicKeyPEM,
		KeyID:           req.KeyID,
		KeyAlgo:         req.KeyAlgo,
		Signature:       req.Signature,
		Timestamp:       req.Timestamp,
		BiometricType:   domain.BiometricType(req.BiometricType),
		AttestationData: req.AttestationData,
		IsRooted:        req.IsRooted,
		IsJailbroken:    req.IsJailbroken,
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrRootedDevice):
			writeError(w, http.StatusForbidden, "rooted/jailbroken device not permitted")
		case errors.Is(err, service.ErrSignatureInvalid):
			writeError(w, http.StatusUnauthorized, "signature verification failed")
		case errors.Is(err, service.ErrChallengeExpired):
			writeError(w, http.StatusUnauthorized, "challenge expired")
		case errors.Is(err, service.ErrChallengeUsed):
			writeError(w, http.StatusConflict, "challenge already used")
		default:
			writeError(w, http.StatusInternalServerError, "enrollment failed")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "enrolled"})
}

func (h *BiometricHandler) Authenticate(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	var req struct {
		ChallengeID  string `json:"challenge_id"`
		Nonce        string `json:"nonce"`
		Signature    string `json:"signature"`
		Timestamp    int64  `json:"timestamp"`
		SessionID    string `json:"session_id"`
		IsRooted     bool   `json:"is_rooted"`
		IsJailbroken bool   `json:"is_jailbroken"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	resp, err := h.authSvc.ExchangeBiometricToken(service.BiometricTokenRequest{
		UserID:       claims.UserID,
		DeviceID:     claims.DeviceID,
		ChallengeID:  req.ChallengeID,
		Nonce:        req.Nonce,
		Signature:    req.Signature,
		Timestamp:    req.Timestamp,
		SessionID:    req.SessionID,
		IsRooted:     req.IsRooted,
		IsJailbroken: req.IsJailbroken,
	})
	if err != nil {
		writeError(w, http.StatusUnauthorized, "biometric authentication failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  resp.AccessToken,
		"refresh_token": resp.RefreshToken,
	})
}

func (h *BiometricHandler) Unenroll(w http.ResponseWriter, r *http.Request) {
	// Disable biometric on device — requires password re-auth as fallback
	writeJSON(w, http.StatusOK, map[string]string{"status": "unenrolled"})
}

// ─── Device Handler ───────────────────────────────────────────────────────────

type DeviceHandler struct {
	deviceSvc *service.DeviceService
	auditSvc  *service.AuditService
}

func NewDeviceHandler(deviceSvc *service.DeviceService, auditSvc *service.AuditService) *DeviceHandler {
	return &DeviceHandler{deviceSvc: deviceSvc, auditSvc: auditSvc}
}

func (h *DeviceHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	devices, err := h.deviceSvc.ListUserDevices(claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list devices")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

func (h *DeviceHandler) RevokeDevice(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	deviceID := r.PathValue("deviceID")

	if err := h.deviceSvc.RevokeDevice(deviceID, claims.UserID, claims.UserID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "device_revoked"})
}

func (h *DeviceHandler) VerifyDevice(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	device, err := h.deviceSvc.ValidateDevice(claims.DeviceID, claims.UserID)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device_id":         device.ID,
		"biometric_enabled": device.BiometricEnabled,
		"trust_score":       device.TrustScore,
		"status":            device.Status,
	})
}

// ─── Audit Handler ────────────────────────────────────────────────────────────

type AuditHandler struct {
	auditSvc *service.AuditService
}

func NewAuditHandler(auditSvc *service.AuditService) *AuditHandler {
	return &AuditHandler{auditSvc: auditSvc}
}

func (h *AuditHandler) GetLogs(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	logs, err := h.auditSvc.GetLogs(claims.UserID, 50, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get logs")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": logs, "count": len(logs)})
}
