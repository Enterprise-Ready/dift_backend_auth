package auth

import (
	"context"

	"dift_backend_go/auth-service/internal/dto"
)

type QueryService interface {
	Me(ctx context.Context, accessToken string) (*dto.UserProfile, error)
}
