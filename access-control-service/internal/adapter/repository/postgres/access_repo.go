package postgresrepo

import (
	"context"
	"encoding/json"
	"github.com/diftapp/identity-platform/access-control-service/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repo struct{ db *pgxpool.Pool }

func New(db *pgxpool.Pool) *Repo { return &Repo{db: db} }

func scanUser(row pgx.Row) (domain.User, error) {
	var u domain.User
	var meta []byte
	err := row.Scan(&u.ID, &u.Email, &u.Phone, &u.DisplayName, &u.Status, &meta, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return u, err
	}
	_ = json.Unmarshal(meta, &u.Metadata)
	return u, nil
}

func (r *Repo) CreateUser(ctx context.Context, u domain.User) (domain.User, error) {
	meta, _ := json.Marshal(u.Metadata)
	return scanUser(r.db.QueryRow(ctx, `insert into users(id,email,phone,display_name,status,metadata,created_at,updated_at) values($1,$2,$3,$4,$5,$6,$7,$8) returning id,email,phone,display_name,status,metadata,created_at,updated_at`, u.ID, u.Email, u.Phone, u.DisplayName, u.Status, meta, u.CreatedAt, u.UpdatedAt))
}

func (r *Repo) GetUserByID(ctx context.Context, id string) (domain.User, error) {
	return scanUser(r.db.QueryRow(ctx, `select id,email,phone,display_name,status,metadata,created_at,updated_at from users where id=$1`, id))
}

func (r *Repo) GetUserByEmail(ctx context.Context, email string) (domain.User, error) {
	return scanUser(r.db.QueryRow(ctx, `select id,email,phone,display_name,status,metadata,created_at,updated_at from users where email=$1`, email))
}

func (r *Repo) SetUserStatus(ctx context.Context, id string, status domain.UserStatus) error {
	_, err := r.db.Exec(ctx, `update users set status=$2,updated_at=now() where id=$1`, id, status)
	return err
}

func (r *Repo) ListUsers(ctx context.Context, limit, offset int) ([]domain.User, error) {
	rows, err := r.db.Query(ctx, `select id,email,phone,display_name,status,metadata,created_at,updated_at from users order by created_at desc limit $1 offset $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
func (r *Repo) CreateRole(ctx context.Context, role domain.Role) (domain.Role, error) {
	err := r.db.QueryRow(ctx, `insert into roles(id,name,description,created_at) values($1,$2,$3,now()) returning created_at`, role.ID, role.Name, role.Description).Scan(&role.CreatedAt)
	return role, err
}
func (r *Repo) ListRoles(ctx context.Context) ([]domain.Role, error) {
	rows, err := r.db.Query(ctx, `select id,name,description,created_at from roles order by name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Role{}
	for rows.Next() {
		var x domain.Role
		if err := rows.Scan(&x.ID, &x.Name, &x.Description, &x.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
func (r *Repo) CreatePermission(ctx context.Context, p domain.Permission) (domain.Permission, error) {
	_, err := r.db.Exec(ctx, `insert into permissions(id,key,resource,action,description) values($1,$2,$3,$4,$5)`, p.ID, p.Key, p.Resource, p.Action, p.Description)
	return p, err
}
func (r *Repo) GrantPermissionToRole(ctx context.Context, roleID, permissionID string) error {
	_, err := r.db.Exec(ctx, `insert into role_permissions(role_id,permission_id) values($1,$2) on conflict do nothing`, roleID, permissionID)
	return err
}
func (r *Repo) AssignRole(ctx context.Context, userID, roleID, tenantID string) error {
	_, err := r.db.Exec(ctx, `insert into user_roles(user_id,role_id,tenant_id,created_at) values($1,$2,$3,now()) on conflict do nothing`, userID, roleID, tenantID)
	return err
}
func (r *Repo) RemoveRole(ctx context.Context, userID, roleID, tenantID string) error {
	_, err := r.db.Exec(ctx, `delete from user_roles where user_id=$1 and role_id=$2 and tenant_id=$3`, userID, roleID, tenantID)
	return err
}
func (r *Repo) UserPermissions(ctx context.Context, userID, tenantID string) ([]string, error) {
	rows, err := r.db.Query(ctx, `select distinct p.key from user_roles ur join role_permissions rp on rp.role_id=ur.role_id join permissions p on p.id=rp.permission_id where ur.user_id=$1 and ur.tenant_id=$2`, userID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
