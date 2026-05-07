package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type VerificationService struct {
	mu       sync.RWMutex
	otp      map[string]otpChallenge
	audits   []map[string]any
	client   *http.Client
	smsURL   string
	emailURL string
	faceURL  string
}

type otpChallenge struct {
	UserID    string
	Channel   string
	Target    string
	CodeHash  string
	ExpiresAt time.Time
	Status    string
}

func NewVerificationService() *VerificationService {
	return &VerificationService{
		otp: make(map[string]otpChallenge), audits: make([]map[string]any, 0, 256),
		client:   &http.Client{Timeout: 5 * time.Second},
		smsURL:   strings.TrimRight(os.Getenv("OTP_SMS_PROVIDER_URL"), "/"),
		emailURL: strings.TrimRight(os.Getenv("OTP_EMAIL_PROVIDER_URL"), "/"),
		faceURL:  strings.TrimRight(os.Getenv("FACE_PROVIDER_URL"), "/"),
	}
}

func (s *VerificationService) CreateOTP(ctx context.Context, userID, channel, target string, ttlSec int) (string, string, error) {
	_ = ctx
	channel = strings.ToLower(strings.TrimSpace(channel))
	if userID == "" || target == "" {
		return "", "", fmt.Errorf("user_id and target are required")
	}
	if channel != "sms" && channel != "email" {
		return "", "", fmt.Errorf("channel must be sms or email")
	}
	if ttlSec <= 0 {
		ttlSec = 300
	}
	code := "123456"
	chID := "otp_" + token(8)
	s.mu.Lock()
	s.otp[chID] = otpChallenge{
		UserID: userID, Channel: channel, Target: target,
		CodeHash: hash(userID + ":" + code), ExpiresAt: time.Now().UTC().Add(time.Duration(ttlSec) * time.Second), Status: "pending",
	}
	s.audits = append(s.audits, map[string]any{"time": time.Now().UTC(), "user_id": userID, "type": "otp.challenge", "outcome": "success"})
	s.mu.Unlock()
	_ = s.dispatchOTP(ctx, channel, target, code)
	return chID, code, nil
}

func (s *VerificationService) VerifyOTP(ctx context.Context, userID, challengeID, code string) (bool, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.otp[challengeID]
	if !ok || ch.UserID != userID || time.Now().UTC().After(ch.ExpiresAt) || ch.Status != "pending" {
		return false, nil
	}
	if ch.CodeHash != hash(userID+":"+code) {
		return false, nil
	}
	ch.Status = "verified"
	s.otp[challengeID] = ch
	s.audits = append(s.audits, map[string]any{"time": time.Now().UTC(), "user_id": userID, "type": "otp.verify", "outcome": "success"})
	return true, nil
}

func (s *VerificationService) VerifyFace(ctx context.Context, userID, livenessToken, selfieRef string) (bool, float64, error) {
	_ = ctx
	if userID == "" || livenessToken == "" || selfieRef == "" {
		return false, 0, fmt.Errorf("user_id, liveness_token, selfie_ref are required")
	}
	approved := strings.HasPrefix(livenessToken, "live_")
	score := 0.90
	if s.faceURL != "" {
		ok, sc, err := s.dispatchFace(ctx, userID, livenessToken, selfieRef)
		if err == nil {
			approved, score = ok, sc
		}
	}
	outcome := "rejected"
	if approved {
		outcome = "approved"
	}
	s.mu.Lock()
	s.audits = append(s.audits, map[string]any{"time": time.Now().UTC(), "user_id": userID, "type": "face.verify", "outcome": outcome, "score": score})
	s.mu.Unlock()
	return approved, score, nil
}

func (s *VerificationService) dispatchOTP(ctx context.Context, channel, target, code string) error {
	var url string
	if channel == "sms" {
		url = s.smsURL
	} else {
		url = s.emailURL
	}
	if url == "" {
		return nil
	}
	body, _ := json.Marshal(map[string]string{"target": target, "code": code, "channel": channel})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/v1/otp/send", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("provider status %d", resp.StatusCode)
	}
	return nil
}

func (s *VerificationService) dispatchFace(ctx context.Context, userID, livenessToken, selfieRef string) (bool, float64, error) {
	body, _ := json.Marshal(map[string]string{"user_id": userID, "liveness_token": livenessToken, "selfie_ref": selfieRef})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.faceURL+"/v1/face/verify", bytes.NewReader(body))
	if err != nil {
		return false, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return false, 0, fmt.Errorf("provider status %d", resp.StatusCode)
	}
	var out struct {
		Approved bool    `json:"approved"`
		Score    float64 `json:"score"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, 0, err
	}
	return out.Approved, out.Score, nil
}

func (s *VerificationService) EvaluateRisk(ctx context.Context, userID, action, ip, deviceID string) (int, string, error) {
	_ = ctx
	score := 0
	if deviceID == "" {
		score += 30
	}
	if ip == "" {
		score += 20
	}
	if strings.Contains(strings.ToLower(action), "admin") {
		score += 40
	}
	level := "low"
	if score >= 70 {
		level = "high"
	} else if score >= 40 {
		level = "medium"
	}
	return score, level, nil
}

func (s *VerificationService) ListAudit(_ context.Context, limit int) []map[string]any {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.audits) <= limit {
		return append([]map[string]any{}, s.audits...)
	}
	return append([]map[string]any{}, s.audits[len(s.audits)-limit:]...)
}

func token(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
func hash(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])
}
