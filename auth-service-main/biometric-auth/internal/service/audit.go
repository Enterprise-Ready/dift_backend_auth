package service

import (
	"fmt"
	"time"

	"biometric-auth/internal/domain"
	"biometric-auth/internal/repository"
)

type AuditService struct {
	repo repository.AuditRepository
}

func NewAuditService(repo repository.AuditRepository) *AuditService {
	return &AuditService{repo: repo}
}

func (s *AuditService) Log(log *domain.AuditLog) error {
	if log.ID == "" {
		id, err := secureHex(8)
		if err != nil {
			return err
		}
		log.ID = id
	}
	log.CreatedAt = time.Now()
	return s.repo.Store(log)
}

func (s *AuditService) GetLogs(userID string, limit, offset int) ([]*domain.AuditLog, error) {
	logs, err := s.repo.GetByUser(userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("get audit logs: %w", err)
	}
	return logs, nil
}

func (s *AuditService) GetAllLogs(limit, offset int) ([]*domain.AuditLog, error) {
	return s.repo.GetAll(limit, offset)
}
