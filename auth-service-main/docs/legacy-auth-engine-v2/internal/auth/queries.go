//go:build legacy
// +build legacy

package auth

import (
	"context"

	"github.com/enterprise/auth-engine/internal/models"
	"github.com/google/uuid"
)

// GetUser returns a user by ID (used by handler /me)
func (s *Service) GetUser(ctx context.Context, id uuid.UUID) (*models.User, error) {
	return s.users.GetByID(ctx, id)
}

// GetUserByIdentifier returns a user by email or phone (used by face login)
func (s *Service) GetUserByIdentifier(ctx context.Context, identifier string) (*models.User, error) {
	user, err := s.users.GetByIdentifier(ctx, identifier)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}
