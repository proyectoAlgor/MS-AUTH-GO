package repository

import (
	"database/sql"
	"fmt"
	"time"

	"ms-auth-go/internal/models"

	_ "github.com/lib/pq"
)

type AuthRepository interface {
	// User operations
	CreateUser(user *models.User) error
	GetUserByEmail(email string) (*models.User, error)
	GetUserByID(id string) (*models.User, error)
	GetAllUsers() ([]models.User, error)
	UpdateUser(id string, user *models.User) error
	DeleteUser(id string) error

	// Role operations
	GetAllRoles() ([]models.Role, error)
	GetRoleByID(id int) (*models.Role, error)
	GetRoleByCode(code string) (*models.Role, error)
	GetUserRoles(userID string) ([]models.Role, error)
	AssignRoleToUser(userID string, roleID int) error
	RemoveRoleFromUser(userID string, roleID int) error
	UserHasRole(userID string, roleCode string) (bool, error)

	// Security operations
	RecordLoginAttempt(attempt *models.LoginAttempt) error
	UpdateFailedLoginAttempts(userID string, attempts int) error
	LockUser(userID string, lockedUntil *time.Time) error
	UnlockUser(userID string) error
	GetRecentFailedAttempts(email string, since time.Time) (int, error)
	UpdateUserPassword(userID string, hashedPassword string) error

	// Check if user exists but is deactivated
	GetUserByEmailIncludingInactive(email string) (*models.User, error)

	// Password reset
	ResetUserPassword(userID string, hashedPassword string) error
}

type authRepository struct {
	db *sql.DB
}

func NewAuthRepository(dbURL string) (AuthRepository, error) {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	repo := &authRepository{db: db}

	// Crear roles por defecto si no existen
	if err := repo.createDefaultRoles(); err != nil {
		return nil, fmt.Errorf("failed to create default roles: %w", err)
	}

	return repo, nil
}

func (r *authRepository) CreateUser(user *models.User) error {
	query := `
		INSERT INTO bar_system.users (id, email, password_hash, first_name, last_name, document_number, document_type, 
		                              venue_id, is_active, is_locked, failed_login_attempts, last_failed_login_at, locked_until)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (email) DO NOTHING
		RETURNING id, created_at, updated_at
	`

	err := r.db.QueryRow(query, user.ID, user.Email, user.PasswordHash, user.FirstName, user.LastName,
		user.DocumentNumber, user.DocumentType, user.VenueID, user.IsActive, user.IsLocked,
		user.FailedLoginAttempts, user.LastFailedLoginAt, user.LockedUntil).
		Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)

	return err
}

func (r *authRepository) GetUserByEmail(email string) (*models.User, error) {
	query := `
		SELECT id, email, password_hash, first_name, last_name, document_number, document_type, venue_id, 
		       is_active, is_locked, failed_login_attempts, last_failed_login_at, locked_until, created_at, updated_at
		FROM bar_system.users 
		WHERE email = $1 AND is_active = true
	`

	user := &models.User{}
	err := r.db.QueryRow(query, email).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName,
		&user.DocumentNumber, &user.DocumentType, &user.VenueID, &user.IsActive, &user.IsLocked,
		&user.FailedLoginAttempts, &user.LastFailedLoginAt, &user.LockedUntil, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *authRepository) GetUserByID(id string) (*models.User, error) {
	query := `
		SELECT id, email, password_hash, first_name, last_name, document_number, document_type, venue_id, 
		       is_active, is_locked, failed_login_attempts, last_failed_login_at, locked_until, created_at, updated_at
		FROM bar_system.users 
		WHERE id = $1
	`

	user := &models.User{}
	err := r.db.QueryRow(query, id).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName,
		&user.DocumentNumber, &user.DocumentType, &user.VenueID, &user.IsActive, &user.IsLocked,
		&user.FailedLoginAttempts, &user.LastFailedLoginAt, &user.LockedUntil, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *authRepository) GetAllUsers() ([]models.User, error) {
	query := `
		SELECT id, email, password_hash, first_name, last_name, document_number, document_type, venue_id, 
		       is_active, is_locked, failed_login_attempts, last_failed_login_at, locked_until, created_at, updated_at
		FROM bar_system.users 
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		var firstName, lastName sql.NullString
		var documentNumber, documentType sql.NullString
		var venueID sql.NullString

		err := rows.Scan(&user.ID, &user.Email, &user.PasswordHash, &firstName, &lastName,
			&documentNumber, &documentType, &venueID, &user.IsActive, &user.IsLocked,
			&user.FailedLoginAttempts, &user.LastFailedLoginAt, &user.LockedUntil, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			return nil, err
		}

		// Handle NULL values
		user.FirstName = firstName.String
		user.LastName = lastName.String
		user.DocumentNumber = documentNumber.String
		user.DocumentType = documentType.String
		if venueID.Valid {
			user.VenueID = &venueID.String
		}

		users = append(users, user)
	}

	return users, nil
}

func (r *authRepository) UpdateUser(id string, user *models.User) error {
	query := `
		UPDATE bar_system.users 
		SET email = $1, first_name = $2, last_name = $3, document_number = $4, document_type = $5, venue_id = $6, is_active = $7
		WHERE id = $8
	`

	_, err := r.db.Exec(query, user.Email, user.FirstName, user.LastName, user.DocumentNumber, user.DocumentType, user.VenueID, user.IsActive, id)
	return err
}

func (r *authRepository) DeleteUser(id string) error {
	query := `
		UPDATE bar_system.users 
		SET is_active = false, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`

	_, err := r.db.Exec(query, id)
	return err
}

// ================================================
// Role operations
// ================================================

func (r *authRepository) GetAllRoles() ([]models.Role, error) {
	query := `
		SELECT id, code, name
		FROM bar_system.roles 
		WHERE is_active = true
		ORDER BY id
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []models.Role
	for rows.Next() {
		var role models.Role
		err := rows.Scan(&role.ID, &role.Code, &role.Name)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, nil
}

func (r *authRepository) GetRoleByID(id int) (*models.Role, error) {
	query := `SELECT id, code, name FROM bar_system.roles WHERE id = $1`

	role := &models.Role{}
	err := r.db.QueryRow(query, id).Scan(&role.ID, &role.Code, &role.Name)

	if err != nil {
		return nil, err
	}

	return role, nil
}

func (r *authRepository) GetRoleByCode(code string) (*models.Role, error) {
	query := `SELECT id, code, name FROM bar_system.roles WHERE code = $1`

	role := &models.Role{}
	err := r.db.QueryRow(query, code).Scan(&role.ID, &role.Code, &role.Name)

	if err != nil {
		return nil, err
	}

	return role, nil
}

func (r *authRepository) GetUserRoles(userID string) ([]models.Role, error) {
	query := `
		SELECT r.id, r.code, r.name
		FROM bar_system.roles r
		JOIN bar_system.user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
	`

	rows, err := r.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []models.Role
	for rows.Next() {
		var role models.Role
		err := rows.Scan(&role.ID, &role.Code, &role.Name)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, nil
}

func (r *authRepository) AssignRoleToUser(userID string, roleID int) error {
	query := `
		INSERT INTO bar_system.user_roles (user_id, role_id)
		VALUES ($1, $2)
		ON CONFLICT (user_id, role_id) DO NOTHING
	`

	_, err := r.db.Exec(query, userID, roleID)
	return err
}

func (r *authRepository) RemoveRoleFromUser(userID string, roleID int) error {
	query := `
		DELETE FROM bar_system.user_roles
		WHERE user_id = $1 AND role_id = $2
	`

	_, err := r.db.Exec(query, userID, roleID)
	return err
}

func (r *authRepository) UserHasRole(userID string, roleCode string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 
			FROM bar_system.user_roles ur
			JOIN bar_system.roles r ON ur.role_id = r.id
			WHERE ur.user_id = $1 AND r.code = $2
		)
	`

	var exists bool
	err := r.db.QueryRow(query, userID, roleCode).Scan(&exists)
	return exists, err
}

func (r *authRepository) createDefaultRoles() error {
	roles := []struct {
		code string
		name string
	}{
		{"admin", "Administrador"},
		{"cashier", "Cajero"},
		{"waiter", "Mesero"},
	}

	for _, role := range roles {
		query := `
			INSERT INTO bar_system.roles (code, name)
			VALUES ($1, $2)
			ON CONFLICT (code) DO NOTHING
		`
		_, err := r.db.Exec(query, role.code, role.name)
		if err != nil {
			return fmt.Errorf("failed to create role %s: %w", role.code, err)
		}
	}

	return nil
}

// ================================================
// Security operations implementation
// ================================================

func (r *authRepository) RecordLoginAttempt(attempt *models.LoginAttempt) error {
	query := `
		INSERT INTO bar_system.login_attempts (id, user_id, email, ip_address, user_agent, success, attempted_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := r.db.Exec(query, attempt.ID, attempt.UserID, attempt.Email, attempt.IPAddress, attempt.UserAgent, attempt.Success, attempt.AttemptedAt)
	if err != nil {
		return fmt.Errorf("failed to record login attempt: %w", err)
	}
	return nil
}

func (r *authRepository) UpdateFailedLoginAttempts(userID string, attempts int) error {
	query := `
		UPDATE bar_system.users 
		SET failed_login_attempts = $1, 
		    last_failed_login_at = CURRENT_TIMESTAMP,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = $2
	`
	_, err := r.db.Exec(query, attempts, userID)
	if err != nil {
		return fmt.Errorf("failed to update failed login attempts: %w", err)
	}
	return nil
}

func (r *authRepository) LockUser(userID string, lockedUntil *time.Time) error {
	query := `
		UPDATE bar_system.users 
		SET is_locked = TRUE, 
		    locked_until = $1,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = $2
	`
	_, err := r.db.Exec(query, lockedUntil, userID)
	if err != nil {
		return fmt.Errorf("failed to lock user: %w", err)
	}
	return nil
}

func (r *authRepository) UnlockUser(userID string) error {
	query := `
		UPDATE bar_system.users 
		SET is_locked = FALSE, 
		    locked_until = NULL,
		    failed_login_attempts = 0,
		    last_failed_login_at = NULL,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`
	_, err := r.db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to unlock user: %w", err)
	}
	return nil
}

func (r *authRepository) GetRecentFailedAttempts(email string, since time.Time) (int, error) {
	query := `
		SELECT COUNT(*) 
		FROM bar_system.login_attempts 
		WHERE email = $1 
		  AND success = FALSE 
		  AND attempted_at > $2
	`
	var count int
	err := r.db.QueryRow(query, email, since).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get recent failed attempts: %w", err)
	}
	return count, nil
}

func (r *authRepository) ResetUserPassword(userID string, hashedPassword string) error {
	query := `
		UPDATE bar_system.users 
		SET password_hash = $1, updated_at = CURRENT_TIMESTAMP
		WHERE id = $2
	`

	_, err := r.db.Exec(query, hashedPassword, userID)
	return err
}

func (r *authRepository) UpdateUserPassword(userID string, hashedPassword string) error {
	query := `
		UPDATE bar_system.users 
		SET password_hash = $1, updated_at = CURRENT_TIMESTAMP
		WHERE id = $2
	`

	_, err := r.db.Exec(query, hashedPassword, userID)
	return err
}

func (r *authRepository) GetUserByEmailIncludingInactive(email string) (*models.User, error) {
	query := `
		SELECT id, email, password_hash, first_name, last_name, document_number, document_type, venue_id, 
		       is_active, is_locked, failed_login_attempts, last_failed_login_at, locked_until, created_at, updated_at
		FROM bar_system.users 
		WHERE email = $1
	`

	user := &models.User{}
	err := r.db.QueryRow(query, email).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName,
		&user.DocumentNumber, &user.DocumentType, &user.VenueID, &user.IsActive, &user.IsLocked,
		&user.FailedLoginAttempts, &user.LastFailedLoginAt, &user.LockedUntil, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return user, nil
}
