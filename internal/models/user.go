package models

import (
	"time"
)

type User struct {
	ID                  string     `json:"id" db:"id"`
	Email               string     `json:"email" db:"email"`
	PasswordHash        string     `json:"-" db:"password_hash"`
	FirstName           string     `json:"first_name" db:"first_name"`
	LastName            string     `json:"last_name" db:"last_name"`
	DocumentNumber      string     `json:"document_number" db:"document_number"`
	DocumentType        string     `json:"document_type" db:"document_type"`
	VenueID             *string    `json:"venue_id" db:"venue_id"`
	IsActive            bool       `json:"is_active" db:"is_active"`
	IsLocked            bool       `json:"is_locked" db:"is_locked"`
	FailedLoginAttempts int        `json:"failed_login_attempts" db:"failed_login_attempts"`
	LastFailedLoginAt   *time.Time `json:"last_failed_login_at" db:"last_failed_login_at"`
	LockedUntil         *time.Time `json:"locked_until" db:"locked_until"`
	CreatedAt           time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at" db:"updated_at"`
}

type Role struct {
	ID   int    `json:"id" db:"id"`
	Code string `json:"code" db:"code"`
	Name string `json:"name" db:"name"`
}

type UserRole struct {
	UserID string `json:"user_id" db:"user_id"`
	RoleID int    `json:"role_id" db:"role_id"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type RegisterRequest struct {
	Email          string  `json:"email" binding:"required,email"`
	Password       string  `json:"password" binding:"required,min=6"`
	FirstName      string  `json:"first_name" binding:"required"`
	LastName       string  `json:"last_name" binding:"required"`
	DocumentNumber string  `json:"document_number" binding:"required"`
	DocumentType   string  `json:"document_type" binding:"required"`
	VenueID        *string `json:"venue_id"`
}

type LoginResponse struct {
	Token     string `json:"token"`
	User      User   `json:"user"`
	ExpiresIn int    `json:"expires_in"`
}

type ResetPasswordRequest struct {
	UserID      string `json:"user_id" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"` // Required - admin must provide password
}

type LoginAttempt struct {
	ID          string    `json:"id" db:"id"`
	UserID      *string   `json:"user_id" db:"user_id"`
	Email       string    `json:"email" db:"email"`
	IPAddress   string    `json:"ip_address" db:"ip_address"`
	UserAgent   string    `json:"user_agent" db:"user_agent"`
	Success     bool      `json:"success" db:"success"`
	AttemptedAt time.Time `json:"attempted_at" db:"attempted_at"`
}
