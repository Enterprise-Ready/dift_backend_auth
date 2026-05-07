package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"dift_backend_go/auth-service/config"
	"dift_backend_go/auth-service/internal/dto"
	repoport "dift_backend_go/auth-service/internal/interface/repository"
	serviceport "dift_backend_go/auth-service/internal/interface/service/auth"
	"dift_backend_go/auth-service/internal/utils"
	"dift_backend_go/auth-service/pkg/metrics"
)

type AuthService struct {
	cfg      *config.AppConfig
	identity repoport.IdentityGateway
}

func NewAuthService(cfg *config.AppConfig, identity repoport.IdentityGateway) *AuthService {
	return &AuthService{cfg: cfg, identity: identity}
}

var _ serviceport.CommandService = (*AuthService)(nil)
var _ serviceport.QueryService = (*AuthService)(nil)

func (s *AuthService) RegisterEmail(ctx context.Context, req dto.RegisterEmailRequest) (*dto.AuthResponse, error) {
	defer func(start time.Time) { metrics.ObserveAuthLatency(start, "register") }(time.Now())
	hashed, err := utils.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}
	user, err := s.identity.CreateEmailUser(ctx, req.Name, req.Email, hashed)
	if err != nil {
		return nil, err
	}
	return s.buildAuthResponse(ctx, user)
}

func (s *AuthService) LoginEmail(ctx context.Context, req dto.LoginEmailRequest) (*dto.AuthResponse, error) {
	defer func(start time.Time) { metrics.ObserveAuthLatency(start, "login") }(time.Now())
	user, err := s.identity.GetUserByEmail(ctx, req.Email)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}
	if err := utils.CheckPassword(req.Password, user.Password); err != nil {
		return nil, errors.New("invalid credentials")
	}
	return s.buildAuthResponse(ctx, user)
}

func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*dto.AuthResponse, error) {
	defer func(start time.Time) { metrics.ObserveAuthLatency(start, "refresh") }(time.Now())
	claims, err := utils.ParseJWT(refreshToken, s.cfg.Auth.RefreshJWTSecret)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}
	if claims.TokenType != "refresh" {
		return nil, errors.New("invalid token type")
	}

	user, err := s.identity.GetUserByEmail(ctx, claims.Email)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}
	if user.ID != claims.Sub {
		return nil, errors.New("token subject mismatch")
	}
	return s.buildAuthResponse(ctx, user)
}

func (s *AuthService) Me(ctx context.Context, accessToken string) (*dto.UserProfile, error) {
	claims, err := utils.ParseJWT(accessToken, s.cfg.Auth.JWTSecret)
	if err != nil {
		return nil, errors.New("invalid access token")
	}
	if claims.TokenType != "access" {
		return nil, errors.New("invalid token type")
	}
	return &dto.UserProfile{
		ID:    claims.Sub,
		Name:  claims.Name,
		Email: claims.Email,
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	_, _ = ctx, refreshToken
	return nil
}

func (s *AuthService) buildAuthResponse(ctx context.Context, user *repoport.IdentityUser) (*dto.AuthResponse, error) {
	roles, _ := s.identity.GetUserRoles(ctx, user.ID)
	roleNames := make([]string, 0, len(roles))
	for _, r := range roles {
		roleNames = append(roleNames, r.Name)
	}
	role := strings.Join(roleNames, ",")

	access, err := utils.GenerateJWT(user.ID, user.Name, user.Email, role, "access", s.cfg.Auth.JWTSecret, s.cfg.Auth.AccessTokenExpires)
	if err != nil {
		return nil, err
	}
	refresh, err := utils.GenerateJWT(user.ID, user.Name, user.Email, role, "refresh", s.cfg.Auth.RefreshJWTSecret, s.cfg.Auth.RefreshTokenExpires)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		User:         dto.UserProfile{ID: user.ID, Name: user.Name, Email: user.Email, Phone: user.Phone},
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}
