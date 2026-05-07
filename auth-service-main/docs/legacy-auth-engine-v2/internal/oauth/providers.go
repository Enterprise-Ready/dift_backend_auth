//go:build legacy
// +build legacy

package oauth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/enterprise/auth-engine/internal/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// ─── User Info ────────────────────────────────────────────────────────────────

type ProviderUser struct {
	ProviderUID string
	Provider    string
	Email       *string
	DisplayName string
	AvatarURL   *string
	Phone       *string
	Verified    bool
	RawData     map[string]interface{}
}

// ─── Interface ────────────────────────────────────────────────────────────────

type Provider interface {
	ExchangeToken(ctx context.Context, code string) (*oauth2.Token, error)
	GetUserInfo(ctx context.Context, token *oauth2.Token) (*ProviderUser, error)
	VerifyIDToken(ctx context.Context, idToken string) (*ProviderUser, error)
}

// ─── Google ───────────────────────────────────────────────────────────────────

type GoogleProvider struct {
	cfg    *config.GoogleOAuthConfig
	oauth2 *oauth2.Config
	http   *http.Client
}

func NewGoogleProvider(cfg *config.GoogleOAuthConfig) *GoogleProvider {
	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
		Endpoint:     google.Endpoint,
	}
	if len(oauthCfg.Scopes) == 0 {
		oauthCfg.Scopes = []string{"openid", "email", "profile"}
	}
	return &GoogleProvider{
		cfg:    cfg,
		oauth2: oauthCfg,
		http:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *GoogleProvider) ExchangeToken(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.oauth2.Exchange(ctx, code)
}

func (p *GoogleProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*ProviderUser, error) {
	client := p.oauth2.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, fmt.Errorf("google userinfo: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("google parse userinfo: %w", err)
	}

	user := &ProviderUser{
		ProviderUID: info.Sub,
		Provider:    "google",
		DisplayName: info.Name,
		Verified:    info.EmailVerified,
	}
	if info.Email != "" {
		user.Email = &info.Email
	}
	if info.Picture != "" {
		user.AvatarURL = &info.Picture
	}
	return user, nil
}

func (p *GoogleProvider) VerifyIDToken(ctx context.Context, idToken string) (*ProviderUser, error) {
	// Verify via Google's tokeninfo endpoint (production: use google-auth-library or verify JWT signature directly)
	url := fmt.Sprintf("https://oauth2.googleapis.com/tokeninfo?id_token=%s", idToken)
	resp, err := p.http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("google verify id_token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google: invalid id_token (status %d)", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var info struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified string `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		Aud           string `json:"aud"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	if info.Aud != p.cfg.ClientID {
		return nil, fmt.Errorf("google: id_token audience mismatch")
	}

	user := &ProviderUser{
		ProviderUID: info.Sub,
		Provider:    "google",
		DisplayName: info.Name,
		Verified:    info.EmailVerified == "true",
	}
	if info.Email != "" {
		user.Email = &info.Email
	}
	if info.Picture != "" {
		user.AvatarURL = &info.Picture
	}
	return user, nil
}

// ─── Apple ────────────────────────────────────────────────────────────────────

type AppleProvider struct {
	cfg       *config.AppleOAuthConfig
	http      *http.Client
	publicKey *rsa.PublicKey
}

func NewAppleProvider(cfg *config.AppleOAuthConfig) *AppleProvider {
	return &AppleProvider{
		cfg:  cfg,
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *AppleProvider) ExchangeToken(ctx context.Context, code string) (*oauth2.Token, error) {
	// Apple uses PKCE + client_secret JWT signed with ES256
	// In production: generate client_secret JWT from private key, then POST to Apple's token endpoint
	// https://appleid.apple.com/auth/token
	return nil, fmt.Errorf("apple: generate client_secret JWT from private key (see Apple Sign In docs)")
}

func (p *AppleProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*ProviderUser, error) {
	// Apple only sends user info on first authorization; extract from id_token JWT claims
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("apple: missing id_token")
	}
	return p.VerifyIDToken(ctx, idToken)
}

func (p *AppleProvider) VerifyIDToken(ctx context.Context, idToken string) (*ProviderUser, error) {
	// Production steps:
	// 1. Fetch Apple's public keys: https://appleid.apple.com/auth/keys
	// 2. Parse JWT header to find kid
	// 3. Verify ES256 signature
	// 4. Validate iss, aud, exp claims

	// Stub - parse JWT payload without verification (add sig verification in production)
	parts := splitJWT(idToken)
	if len(parts) != 3 {
		return nil, fmt.Errorf("apple: invalid id_token format")
	}

	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Aud   string `json:"aud"`
	}
	if err := decodeJWTClaims(parts[1], &claims); err != nil {
		return nil, fmt.Errorf("apple: decode claims: %w", err)
	}

	user := &ProviderUser{
		ProviderUID: claims.Sub,
		Provider:    "apple",
		DisplayName: "",
		Verified:    true,
	}
	if claims.Email != "" {
		user.Email = &claims.Email
	}
	return user, nil
}

// ─── Registry ─────────────────────────────────────────────────────────────────

type Registry struct {
	providers map[string]Provider
}

func NewRegistry(cfg *config.OAuthConfig) *Registry {
	r := &Registry{providers: make(map[string]Provider)}
	if cfg.Google.ClientID != "" {
		r.providers["google"] = NewGoogleProvider(&cfg.Google)
	}
	if cfg.Apple.ClientID != "" {
		r.providers["apple"] = NewAppleProvider(&cfg.Apple)
	}
	return r
}

func (r *Registry) Get(provider string) (Provider, error) {
	p, ok := r.providers[provider]
	if !ok {
		return nil, fmt.Errorf("oauth provider not configured: %s", provider)
	}
	return p, nil
}

// ─── JWT helpers (no external dep) ───────────────────────────────────────────

import (
	"encoding/base64"
	"strings"
)

func splitJWT(token string) []string {
	return strings.Split(token, ".")
}

func decodeJWTClaims(segment string, v interface{}) error {
	// pad base64
	switch len(segment) % 4 {
	case 2:
		segment += "=="
	case 3:
		segment += "="
	}
	b, err := base64.URLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
