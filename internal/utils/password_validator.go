package utils

import (
	"regexp"
	"strings"
)

// PasswordValidator validates passwords according to ISO 27001 standards
type PasswordValidator struct {
	minLength        int
	requireUppercase bool
	requireLowercase bool
	requireNumbers   bool
	requireSpecial   bool
}

// NewPasswordValidator creates a new password validator with ISO 27001 standards
func NewPasswordValidator() *PasswordValidator {
	return &PasswordValidator{
		minLength:        8,
		requireUppercase: true,
		requireLowercase: true,
		requireNumbers:   true,
		requireSpecial:   true,
	}
}

// ValidatePassword validates a password according to ISO 27001 standards
func (pv *PasswordValidator) ValidatePassword(password string) (bool, []string) {
	var errors []string

	// Check minimum length
	if len(password) < pv.minLength {
		errors = append(errors, "Password must be at least 8 characters")
	}

	// Check for uppercase letter
	if pv.requireUppercase {
		hasUppercase := regexp.MustCompile(`[A-Z]`).MatchString(password)
		if !hasUppercase {
			errors = append(errors, "Add at least one uppercase letter (A-Z)")
		}
	}

	// Check for lowercase letter
	if pv.requireLowercase {
		hasLowercase := regexp.MustCompile(`[a-z]`).MatchString(password)
		if !hasLowercase {
			errors = append(errors, "Add at least one lowercase letter (a-z)")
		}
	}

	// Check for numbers
	if pv.requireNumbers {
		hasNumbers := regexp.MustCompile(`[0-9]`).MatchString(password)
		if !hasNumbers {
			errors = append(errors, "Add at least one number (0-9)")
		}
	}

	// Check for special characters
	if pv.requireSpecial {
		hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~` + "`" + `]`).MatchString(password)
		if !hasSpecial {
			errors = append(errors, "Add at least one special character (!@#$%^&*)")
		}
	}

	// Check for common weak passwords
	weakPasswords := []string{
		"password", "123456", "12345678", "qwerty", "abc123", "password123",
		"admin", "letmein", "welcome", "monkey", "1234567890", "password1",
		"123123", "000000", "123456789", "qwerty123", "admin123",
	}

	passwordLower := strings.ToLower(password)
	for _, weak := range weakPasswords {
		if passwordLower == weak {
			errors = append(errors, "Password is too common and easily guessable")
			break
		}
	}

	return len(errors) == 0, errors
}

// GetPasswordRequirements returns a list of password requirements
func (pv *PasswordValidator) GetPasswordRequirements() []string {
	return []string{
		"Minimum 8 characters",
		"At least one uppercase letter (A-Z)",
		"At least one lowercase letter (a-z)",
		"At least one number (0-9)",
		"At least one special character (!@#$%^&*()_+-=[]{}|;':\",./<>?~`)",
		"Not a common or easily guessable password",
	}
}
