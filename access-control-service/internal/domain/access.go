package domain

import "time"

type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}
type Permission struct {
	ID          string `json:"id"`
	Key         string `json:"key"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
}
type UserRole struct {
	UserID    string    `json:"user_id"`
	RoleID    string    `json:"role_id"`
	TenantID  string    `json:"tenant_id"`
	CreatedAt time.Time `json:"created_at"`
}
type Decision struct {
	Allowed     bool     `json:"allowed"`
	Reason      string   `json:"reason"`
	Permissions []string `json:"permissions"`
}
