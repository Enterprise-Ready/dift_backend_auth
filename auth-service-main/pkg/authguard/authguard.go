package authguard

import (
	"errors"
	"regexp"
	"strings"
)

var emailRE = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

func CleanString(v string) string { return strings.TrimSpace(v) }
func CleanEmail(v string) string  { return strings.ToLower(strings.TrimSpace(v)) }
func Required(name, v string) error {
	if strings.TrimSpace(v) == "" {
		return errors.New(name + " is required")
	}
	return nil
}
func MaxLen(name, v string, n int) error {
	if len(v) > n {
		return errors.New(name + " is too long")
	}
	return nil
}
func ValidateEmail(email string) error {
	if !emailRE.MatchString(strings.TrimSpace(email)) {
		return errors.New("invalid email")
	}
	return nil
}
func StrongPassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	return nil
}
