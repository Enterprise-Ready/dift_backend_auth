package repository

import "context"

type IdentityUser struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`
	Password string `json:"password,omitempty"`
}

type IdentityRole struct {
	Name string `json:"name"`
}

type IdentityGateway interface {
	GetUserByEmail(ctx context.Context, email string) (*IdentityUser, error)
	CreateEmailUser(ctx context.Context, name, email, password string) (*IdentityUser, error)
	GetUserRoles(ctx context.Context, userID string) ([]IdentityRole, error)
	Health(ctx context.Context) error
}
