package domain

import "time"

type UserStatus string

const (
	UserPending  UserStatus = "pending"
	UserActive   UserStatus = "active"
	UserLocked   UserStatus = "locked"
	UserDisabled UserStatus = "disabled"
	UserDeleted  UserStatus = "deleted"
)

type User struct {
	ID          string         `json:"id"`
	Email       string         `json:"email"`
	Phone       string         `json:"phone"`
	DisplayName string         `json:"display_name"`
	Status      UserStatus     `json:"status"`
	Metadata    map[string]any `json:"metadata"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}
