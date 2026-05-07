//go:build legacy
// +build legacy

package worker

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// ─── Interfaces ───────────────────────────────────────────────────────────────

type SessionCleaner interface {
	CleanupExpired(ctx context.Context) (int64, error)
}

type AuditCleaner interface {
	Cleanup(ctx context.Context) error
}

// ─── Scheduler ────────────────────────────────────────────────────────────────

type Scheduler struct {
	sessions SessionCleaner
	audits   AuditCleaner
	log      *zap.Logger
}

func NewScheduler(sessions SessionCleaner, audits AuditCleaner, log *zap.Logger) *Scheduler {
	return &Scheduler{sessions: sessions, audits: audits, log: log}
}

func (s *Scheduler) Start(ctx context.Context) {
	go s.runEvery(ctx, "session-cleanup", 1*time.Hour, s.cleanSessions)
	go s.runEvery(ctx, "audit-cleanup", 24*time.Hour, s.cleanAudit)
}

func (s *Scheduler) runEvery(ctx context.Context, name string, interval time.Duration, fn func(context.Context)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.log.Info("worker started", zap.String("job", name), zap.Duration("interval", interval))

	for {
		select {
		case <-ticker.C:
			start := time.Now()
			fn(ctx)
			s.log.Info("job completed", zap.String("job", name), zap.Duration("duration", time.Since(start)))
		case <-ctx.Done():
			s.log.Info("worker stopped", zap.String("job", name))
			return
		}
	}
}

func (s *Scheduler) cleanSessions(ctx context.Context) {
	count, err := s.sessions.CleanupExpired(ctx)
	if err != nil {
		s.log.Error("session cleanup failed", zap.Error(err))
		return
	}
	s.log.Info("sessions cleaned", zap.Int64("deleted", count))
}

func (s *Scheduler) cleanAudit(ctx context.Context) {
	if err := s.audits.Cleanup(ctx); err != nil {
		s.log.Error("audit cleanup failed", zap.Error(err))
	}
}
