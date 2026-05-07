package http

import "context"

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type RegisterRequest struct {
	Name     string `json:"name" binding:"required,min=2,max=100"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8,max=72"`
}

type AuthResponse struct {
	UserID       string `json:"user_id"`
	Name         string `json:"name"`
	Email        string `json:"email,omitempty"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type AuthHTTPPort interface {
	LoginEmail(ctx context.Context, req LoginRequest) (*AuthResponse, error)
	RegisterEmail(ctx context.Context, req RegisterRequest) (*AuthResponse, error)
}
