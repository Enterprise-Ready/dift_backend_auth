//go:build legacy
// +build legacy

package validator

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// Common leaked passwords (extend with haveibeenpwned API in production)
var commonPasswords = map[string]bool{
	"password": true, "123456": true, "password1": true,
	"qwerty": true, "abc123": true, "letmein": true,
	"monkey": true, "1234567890": true, "iloveyou": true,
}

type PasswordPolicy struct {
	MinLength        int
	MaxLength        int
	RequireUpper     bool
	RequireLower     bool
	RequireDigit     bool
	RequireSpecial   bool
	ForbidCommon     bool
	ForbidRepeat     int  // max consecutive same chars (0 = disabled)
	ForbidSequential bool // no "abc", "123"
}

var DefaultPolicy = PasswordPolicy{
	MinLength:        8,
	MaxLength:        128,
	RequireUpper:     true,
	RequireLower:     true,
	RequireDigit:     true,
	RequireSpecial:   false,
	ForbidCommon:     true,
	ForbidRepeat:     3,
	ForbidSequential: true,
}

var EnterprisePolicy = PasswordPolicy{
	MinLength:        12,
	MaxLength:        128,
	RequireUpper:     true,
	RequireLower:     true,
	RequireDigit:     true,
	RequireSpecial:   true,
	ForbidCommon:     true,
	ForbidRepeat:     3,
	ForbidSequential: true,
}

type ValidationError struct {
	Violations []string
}

func (e *ValidationError) Error() string {
	return strings.Join(e.Violations, "; ")
}

func ValidatePassword(password string, policy PasswordPolicy) error {
	var violations []string

	if len(password) < policy.MinLength {
		violations = append(violations, fmt.Sprintf("must be at least %d characters", policy.MinLength))
	}
	if policy.MaxLength > 0 && len(password) > policy.MaxLength {
		violations = append(violations, fmt.Sprintf("must be at most %d characters", policy.MaxLength))
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			hasSpecial = true
		}
	}

	if policy.RequireUpper && !hasUpper {
		violations = append(violations, "must contain at least one uppercase letter")
	}
	if policy.RequireLower && !hasLower {
		violations = append(violations, "must contain at least one lowercase letter")
	}
	if policy.RequireDigit && !hasDigit {
		violations = append(violations, "must contain at least one digit")
	}
	if policy.RequireSpecial && !hasSpecial {
		violations = append(violations, "must contain at least one special character")
	}

	if policy.ForbidCommon && commonPasswords[strings.ToLower(password)] {
		violations = append(violations, "password is too common")
	}

	if policy.ForbidRepeat > 0 {
		if hasRepeatingChars(password, policy.ForbidRepeat) {
			violations = append(violations, fmt.Sprintf("must not contain more than %d consecutive identical characters", policy.ForbidRepeat))
		}
	}

	if policy.ForbidSequential && hasSequentialChars(password) {
		violations = append(violations, "must not contain sequential characters (e.g. 'abc', '123')")
	}

	if len(violations) > 0 {
		return &ValidationError{Violations: violations}
	}
	return nil
}

func hasRepeatingChars(s string, max int) bool {
	count := 1
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1] {
			count++
			if count > max {
				return true
			}
		} else {
			count = 1
		}
	}
	return false
}

var sequentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz`),
	regexp.MustCompile(`012|123|234|345|456|567|678|789|890`),
	regexp.MustCompile(`(?i)qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm`),
}

func hasSequentialChars(s string) bool {
	lower := strings.ToLower(s)
	for _, re := range sequentialPatterns {
		if re.MatchString(lower) {
			return true
		}
	}
	return false
}

// Strength returns 0-4 (weak → very strong)
func Strength(password string) int {
	score := 0
	if len(password) >= 8 {
		score++
	}
	if len(password) >= 12 {
		score++
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			hasSpecial = true
		}
	}
	variety := 0
	for _, b := range []bool{hasUpper, hasLower, hasDigit, hasSpecial} {
		if b {
			variety++
		}
	}
	if variety >= 3 {
		score++
	}
	if variety == 4 && len(password) >= 12 {
		score++
	}
	if score > 4 {
		score = 4
	}
	return score
}
