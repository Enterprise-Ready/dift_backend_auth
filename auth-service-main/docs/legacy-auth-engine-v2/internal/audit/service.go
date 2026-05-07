//go:build legacy
// +build legacy

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/enterprise/auth-engine/internal/config"
	"github.com/enterprise/auth-engine/internal/models"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ─── Repository ───────────────────────────────────────────────────────────────

type Repository interface {
	Save(ctx context.Context, log *models.AuditLog) error
	ListByUser(ctx context.Context, userID uuid.UUID, limit int) ([]*models.AuditLog, error)
	ListByAction(ctx context.Context, action string, from, to time.Time) ([]*models.AuditLog, error)
	DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
}

// ─── Service ──────────────────────────────────────────────────────────────────

type Service struct {
	repo       Repository
	cfg        *config.AuditConfig
	httpClient *http.Client
	log        *zap.Logger
}

func NewService(repo Repository, cfg *config.AuditConfig, log *zap.Logger) *Service {
	return &Service{
		repo:       repo,
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		log:        log,
	}
}

func (s *Service) Log(ctx context.Context, entry *models.AuditLog) error {
	if !s.cfg.Enabled {
		return nil
	}

	if err := s.repo.Save(ctx, entry); err != nil {
		s.log.Error("save audit log", zap.Error(err))
		return err
	}

	// Async webhook notification for high-risk events
	if entry.RiskScore >= 0.7 && s.cfg.WebhookURL != "" {
		go s.webhookNotify(entry)
	}

	return nil
}

func (s *Service) GetUserHistory(ctx context.Context, userID uuid.UUID, limit int) ([]*models.AuditLog, error) {
	return s.repo.ListByUser(ctx, userID, limit)
}

func (s *Service) Cleanup(ctx context.Context) error {
	cutoff := time.Now().AddDate(0, 0, -s.cfg.RetentionDays)
	count, err := s.repo.DeleteOlderThan(ctx, cutoff)
	if err != nil {
		return err
	}
	s.log.Info("audit cleanup", zap.Int64("deleted", count))
	return nil
}

func (s *Service) webhookNotify(entry *models.AuditLog) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	payload, err := json.Marshal(map[string]interface{}{
		"event":      "high_risk_activity",
		"audit_log":  entry,
		"timestamp":  time.Now().UTC(),
	})
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.WebhookURL, bytes.NewBuffer(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.log.Warn("audit webhook failed", zap.Error(err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		s.log.Warn("audit webhook bad status", zap.Int("status", resp.StatusCode))
	}
}

// ─── Risk Engine ──────────────────────────────────────────────────────────────

type RiskEngine struct {
	repo Repository
	log  *zap.Logger
}

func NewRiskEngine(repo Repository, log *zap.Logger) *RiskEngine {
	return &RiskEngine{repo: repo, log: log}
}

type RiskAssessment struct {
	Score    float32           `json:"score"`
	Factors  []string          `json:"factors"`
	Decision string            `json:"decision"` // allow, challenge, block
}

func (re *RiskEngine) Assess(ctx context.Context, userID *uuid.UUID, ip, ua string) (*RiskAssessment, error) {
	assessment := &RiskAssessment{Factors: []string{}}
	var score float32

	if userID != nil {
		// Check recent failed logins
		logs, err := re.repo.ListByUser(ctx, *userID, 20)
		if err == nil {
			failCount := 0
			cutoff := time.Now().Add(-1 * time.Hour)
			for _, l := range logs {
				if l.Action == "login" && l.Status == "failure" && l.CreatedAt.After(cutoff) {
					failCount++
				}
			}
			if failCount >= 3 {
				score += 0.4
				assessment.Factors = append(assessment.Factors, fmt.Sprintf("recent_failures:%d", failCount))
			}
		}
	}

	// Unknown user agent
	if ua == "" {
		score += 0.2
		assessment.Factors = append(assessment.Factors, "missing_user_agent")
	}

	// Empty IP (proxy/TOR - check against known lists in production)
	if ip == "127.0.0.1" || ip == "" {
		score += 0.1
		assessment.Factors = append(assessment.Factors, "loopback_ip")
	}

	// Unusual time (UTC)
	hour := time.Now().UTC().Hour()
	if hour >= 0 && hour <= 5 {
		score += 0.1
		assessment.Factors = append(assessment.Factors, "unusual_hour")
	}

	assessment.Score = score
	switch {
	case score >= 0.8:
		assessment.Decision = "block"
	case score >= 0.5:
		assessment.Decision = "challenge"
	default:
		assessment.Decision = "allow"
	}

	return assessment, nil
}
