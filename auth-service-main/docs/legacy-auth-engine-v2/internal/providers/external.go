//go:build legacy
// +build legacy

package providers

import (
	"context"
	"fmt"

	firebaseAuth "firebase.google.com/go/v4/auth"
	"github.com/enterprise/auth-engine/internal/config"
	"github.com/enterprise/auth-engine/internal/models"

	firebase "firebase.google.com/go/v4"
	"google.golang.org/api/option"
)

// ─── Firebase Provider ────────────────────────────────────────────────────────

type FirebaseProvider struct {
	client *firebaseAuth.Client
	cfg    *config.FirebaseConfig
}

func NewFirebaseProvider(ctx context.Context, cfg *config.FirebaseConfig) (*FirebaseProvider, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("firebase not enabled")
	}

	app, err := firebase.NewApp(ctx, &firebase.Config{
		ProjectID:     cfg.ProjectID,
		StorageBucket: cfg.StorageBucket,
	}, option.WithCredentialsFile(cfg.ServiceAccount))
	if err != nil {
		return nil, fmt.Errorf("firebase init: %w", err)
	}

	client, err := app.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("firebase auth client: %w", err)
	}

	return &FirebaseProvider{client: client, cfg: cfg}, nil
}

// VerifyIDToken verifies a Firebase ID token and returns a normalized user
func (p *FirebaseProvider) VerifyIDToken(ctx context.Context, idToken string) (*models.User, error) {
	token, err := p.client.VerifyIDToken(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("firebase verify token: %w", err)
	}

	fbUser, err := p.client.GetUser(ctx, token.UID)
	if err != nil {
		return nil, fmt.Errorf("firebase get user: %w", err)
	}

	user := &models.User{
		DisplayName:   fbUser.DisplayName,
		EmailVerified: fbUser.EmailVerified,
		Status:        models.UserStatusActive,
		Role:          "user",
	}

	if fbUser.Email != "" {
		user.Email = &fbUser.Email
	}
	if fbUser.PhoneNumber != "" {
		user.Phone = &fbUser.PhoneNumber
	}
	if fbUser.PhotoURL != "" {
		user.AvatarURL = &fbUser.PhotoURL
	}

	return user, nil
}

// CreateUser creates a user in Firebase
func (p *FirebaseProvider) CreateUser(ctx context.Context, user *models.User) (string, error) {
	params := (&firebaseAuth.UserToCreate{})

	if user.Email != nil {
		params.Email(*user.Email).EmailVerified(user.EmailVerified)
	}
	if user.Phone != nil {
		params.PhoneNumber(*user.Phone)
	}
	params.DisplayName(user.DisplayName)

	fbUser, err := p.client.CreateUser(ctx, params)
	if err != nil {
		return "", fmt.Errorf("firebase create user: %w", err)
	}

	return fbUser.UID, nil
}

// RevokeRefreshTokens revokes all Firebase sessions for a user
func (p *FirebaseProvider) RevokeRefreshTokens(ctx context.Context, uid string) error {
	return p.client.RevokeRefreshTokens(ctx, uid)
}

// SetCustomClaims sets custom JWT claims in Firebase tokens
func (p *FirebaseProvider) SetCustomClaims(ctx context.Context, uid string, claims map[string]interface{}) error {
	return p.client.SetCustomUserClaims(ctx, uid, claims)
}

// ─── Supabase Provider ────────────────────────────────────────────────────────

type SupabaseProvider struct {
	cfg        *config.SupabaseConfig
	httpClient interface{} // supabase-go client
}

func NewSupabaseProvider(cfg *config.SupabaseConfig) (*SupabaseProvider, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("supabase not enabled")
	}
	// Production: initialize supabase client
	// client := supabase.CreateClient(cfg.URL, cfg.ServiceKey)
	return &SupabaseProvider{cfg: cfg}, nil
}

// SyncUser syncs a user to Supabase Auth
func (p *SupabaseProvider) SyncUser(ctx context.Context, user *models.User) error {
	// Production: use Supabase Admin API to create/update user
	// POST /auth/v1/admin/users
	return nil
}

// VerifyJWT verifies a Supabase JWT
func (p *SupabaseProvider) VerifyJWT(ctx context.Context, token string) (map[string]interface{}, error) {
	// Supabase JWTs are standard JWTs signed with the project's JWT secret
	// Verify using standard JWT library with cfg.AnonKey or cfg.ServiceKey
	return nil, fmt.Errorf("supabase jwt verification: implement with supabase jwt secret")
}

// ─── Provider Registry ────────────────────────────────────────────────────────

type ExternalProviders struct {
	Firebase *FirebaseProvider
	Supabase *SupabaseProvider
}

func NewExternalProviders(ctx context.Context, cfg *config.Config) *ExternalProviders {
	ep := &ExternalProviders{}

	if cfg.Firebase.Enabled {
		fb, err := NewFirebaseProvider(ctx, &cfg.Firebase)
		if err == nil {
			ep.Firebase = fb
		}
	}

	if cfg.Supabase.Enabled {
		sb, err := NewSupabaseProvider(&cfg.Supabase)
		if err == nil {
			ep.Supabase = sb
		}
	}

	return ep
}
