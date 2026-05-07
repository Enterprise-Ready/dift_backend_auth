package access

import (
	"context"
	"github.com/diftapp/identity-platform/access-control-service/internal/domain"
	"github.com/diftapp/identity-platform/access-control-service/internal/port"
	"github.com/google/uuid"
	"strings"
	"time"
)

type Service struct {
	repo   port.Repository
	events port.EventPublisher
}

func New(repo port.Repository, events port.EventPublisher) *Service {
	return &Service{repo: repo, events: events}
}

type CreateUserCommand struct {
	Email       string         `json:"email"`
	Phone       string         `json:"phone"`
	DisplayName string         `json:"display_name"`
	Metadata    map[string]any `json:"metadata"`
}

func (s *Service) CreateUser(ctx context.Context, cmd CreateUserCommand) (domain.User, error) {
	now := time.Now().UTC()
	u := domain.User{
		ID: uuid.NewString(), Email: strings.ToLower(strings.TrimSpace(cmd.Email)), Phone: strings.TrimSpace(cmd.Phone),
		DisplayName: strings.TrimSpace(cmd.DisplayName), Status: domain.UserPending, Metadata: cmd.Metadata, CreatedAt: now, UpdatedAt: now,
	}
	out, err := s.repo.CreateUser(ctx, u)
	if err == nil {
		_ = s.events.Publish(ctx, "access.user.created", out)
	}
	return out, err
}

func (s *Service) GetUser(ctx context.Context, id string) (domain.User, error) {
	return s.repo.GetUserByID(ctx, id)
}

func (s *Service) ListUsers(ctx context.Context, limit, offset int) ([]domain.User, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	return s.repo.ListUsers(ctx, limit, offset)
}

func (s *Service) ActivateUser(ctx context.Context, id string) error {
	err := s.repo.SetUserStatus(ctx, id, domain.UserActive)
	if err == nil {
		_ = s.events.Publish(ctx, "access.user.activated", map[string]string{"user_id": id})
	}
	return err
}

func (s *Service) LockUser(ctx context.Context, id string) error {
	err := s.repo.SetUserStatus(ctx, id, domain.UserLocked)
	if err == nil {
		_ = s.events.Publish(ctx, "access.user.locked", map[string]string{"user_id": id})
	}
	return err
}
func (s *Service) CreateRole(ctx context.Context, name, desc string) (domain.Role, error) {
	r := domain.Role{ID: uuid.NewString(), Name: strings.TrimSpace(name), Description: desc}
	out, err := s.repo.CreateRole(ctx, r)
	if err == nil {
		_ = s.events.Publish(ctx, "access.role.created", out)
	}
	return out, err
}
func (s *Service) ListRoles(ctx context.Context) ([]domain.Role, error) { return s.repo.ListRoles(ctx) }
func (s *Service) CreatePermission(ctx context.Context, key, res, action, desc string) (domain.Permission, error) {
	p := domain.Permission{ID: uuid.NewString(), Key: key, Resource: res, Action: action, Description: desc}
	out, err := s.repo.CreatePermission(ctx, p)
	if err == nil {
		_ = s.events.Publish(ctx, "access.permission.created", out)
	}
	return out, err
}
func (s *Service) Grant(ctx context.Context, roleID, permissionID string) error {
	err := s.repo.GrantPermissionToRole(ctx, roleID, permissionID)
	if err == nil {
		_ = s.events.Publish(ctx, "access.role.permission.granted", map[string]string{"role_id": roleID, "permission_id": permissionID})
	}
	return err
}
func (s *Service) AssignRole(ctx context.Context, userID, roleID, tenantID string) error {
	if tenantID == "" {
		tenantID = "default"
	}
	err := s.repo.AssignRole(ctx, userID, roleID, tenantID)
	if err == nil {
		_ = s.events.Publish(ctx, "access.user.role.assigned", map[string]string{"user_id": userID, "role_id": roleID, "tenant_id": tenantID})
	}
	return err
}
func (s *Service) Check(ctx context.Context, userID, tenantID, permission string) (domain.Decision, error) {
	if tenantID == "" {
		tenantID = "default"
	}
	perms, err := s.repo.UserPermissions(ctx, userID, tenantID)
	if err != nil {
		return domain.Decision{}, err
	}
	for _, p := range perms {
		if p == permission || p == "*" {
			return domain.Decision{Allowed: true, Reason: "permission granted", Permissions: perms}, nil
		}
	}
	return domain.Decision{Allowed: false, Reason: "permission missing", Permissions: perms}, nil
}
