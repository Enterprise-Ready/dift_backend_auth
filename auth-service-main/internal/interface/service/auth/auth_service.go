package auth

import (
	"context"

	httpport "dift_backend_go/auth-service/internal/interface/http"
)

type AuthService interface {
	LoginEmail(ctx context.Context, req httpport.LoginRequest) (*httpport.AuthResponse, error)
	RegisterEmail(ctx context.Context, req httpport.RegisterRequest) (*httpport.AuthResponse, error)
}
