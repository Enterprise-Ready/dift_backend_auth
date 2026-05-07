package auth

import (
	"context"

	"dift_backend_go/auth-service/internal/dto"
)

type CommandService interface {
	RegisterEmail(ctx context.Context, req dto.RegisterEmailRequest) (*dto.AuthResponse, error)
	LoginEmail(ctx context.Context, req dto.LoginEmailRequest) (*dto.AuthResponse, error)
	RefreshToken(ctx context.Context, refreshToken string) (*dto.AuthResponse, error)
	Logout(ctx context.Context, refreshToken string) error
}
