package port

import (
	"context"
	"github.com/diftapp/identity-platform/access-control-service/internal/domain"
)

type Repository interface {
	CreateUser(ctx context.Context, u domain.User) (domain.User, error)
	GetUserByID(ctx context.Context, id string) (domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (domain.User, error)
	SetUserStatus(ctx context.Context, id string, status domain.UserStatus) error
	ListUsers(ctx context.Context, limit, offset int) ([]domain.User, error)

	CreateRole(ctx context.Context, r domain.Role) (domain.Role, error)
	ListRoles(ctx context.Context) ([]domain.Role, error)
	CreatePermission(ctx context.Context, p domain.Permission) (domain.Permission, error)
	GrantPermissionToRole(ctx context.Context, roleID, permissionID string) error
	AssignRole(ctx context.Context, userID, roleID, tenantID string) error
	RemoveRole(ctx context.Context, userID, roleID, tenantID string) error
	UserPermissions(ctx context.Context, userID, tenantID string) ([]string, error)
}

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload any) error
}
