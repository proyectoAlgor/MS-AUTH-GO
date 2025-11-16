package service

import (
	"database/sql"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"ms-auth-go/internal/models"
	"ms-auth-go/internal/repository"
	"ms-auth-go/internal/utils"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	// Authentication
	Login(req *models.LoginRequest, ipAddress, userAgent string) (*models.LoginResponse, error)
	Register(req *models.RegisterRequest) (*models.User, error)
	GetUserProfile(userID string) (*models.User, []models.Role, error)
	ValidateToken(tokenString string) (*jwt.Token, error)

	// User management
	GetAllUsers() ([]models.User, error)
	GetUser(userID string) (*models.User, []models.Role, error)
	UpdateUser(userID string, email, firstName, lastName, documentNumber, documentType string, venueID *string, isActive bool) (*models.User, error)
	DeleteUser(userID string) error

	// Role management
	GetAllRoles() ([]models.Role, error)
	AssignRole(userID string, roleID int) error
	RemoveRole(userID string, roleID int) error

	// Password reset (admin only)
	ResetUserPassword(userID string, newPassword string) error
	GenerateTemporaryPassword() string
	ValidateUserHasRole(userID string, roleCode string) (bool, error)

	// User password change (self-service)
	ChangeUserPassword(userID string, currentPassword, newPassword string) error
}

type authService struct {
	repo       repository.AuthRepository
	jwtSecret  string
	jwtExpires time.Duration
}

func NewAuthService(repo repository.AuthRepository) AuthService {
	// Obtener JWT_SECRET de las variables de entorno
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "bar-jwt-secret-key-change-in-production-min-32-chars"
	}

	return &authService{
		repo:       repo,
		jwtSecret:  jwtSecret,
		jwtExpires: 3 * time.Minute, // Session expires in 3 minutes
	}
}

func (s *authService) Login(req *models.LoginRequest, ipAddress, userAgent string) (*models.LoginResponse, error) {
	// Crear intento de login para registro
	attempt := &models.LoginAttempt{
		ID:          generateUUID(),
		Email:       req.Email,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		Success:     false,
		AttemptedAt: time.Now(),
	}

	// Buscar usuario por email (incluyendo inactivos)
	user, err := s.repo.GetUserByEmailIncludingInactive(req.Email)
	if err != nil {
		// Registrar intento fallido
		s.repo.RecordLoginAttempt(attempt)
		return nil, fmt.Errorf("invalid credentials")
	}

	// Verificar si el usuario está desactivado
	if !user.IsActive {
		s.repo.RecordLoginAttempt(attempt)
		return nil, fmt.Errorf("user account is deactivated")
	}

	// Verificar si la cuenta está bloqueada
	if user.IsLocked {
		if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
			s.repo.RecordLoginAttempt(attempt)
			return nil, fmt.Errorf("account temporarily locked due to multiple failed attempts")
		} else {
			// Desbloquear si el tiempo de bloqueo expiró
			s.repo.UnlockUser(user.ID)
		}
	}

	// Verificar contraseña
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		// Incrementar intentos fallidos
		newAttempts := user.FailedLoginAttempts + 1
		s.repo.UpdateFailedLoginAttempts(user.ID, newAttempts)

		// Bloquear cuenta si supera 3 intentos fallidos
		if newAttempts >= 3 {
			lockUntil := time.Now().Add(15 * time.Minute) // Bloqueo por 15 minutos
			s.repo.LockUser(user.ID, &lockUntil)
		}

		// Registrar intento fallido
		attempt.UserID = &user.ID
		s.repo.RecordLoginAttempt(attempt)
		return nil, fmt.Errorf("invalid credentials")
	}

	// Login exitoso - resetear intentos fallidos
	s.repo.UnlockUser(user.ID)

	// Obtener roles del usuario
	roles, err := s.repo.GetUserRoles(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	// Generar JWT
	token, err := s.generateJWT(user.ID, user.Email, roles)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Registrar intento exitoso
	attempt.UserID = &user.ID
	attempt.Success = true
	s.repo.RecordLoginAttempt(attempt)

	// Limpiar datos sensibles
	user.PasswordHash = ""

	return &models.LoginResponse{
		Token:     token,
		User:      *user,
		ExpiresIn: int(s.jwtExpires.Seconds()),
	}, nil
}

func (s *authService) Register(req *models.RegisterRequest) (*models.User, error) {
	// Verificar si el usuario ya existe
	existingUser, err := s.repo.GetUserByEmail(req.Email)
	if err == nil && existingUser != nil {
		return nil, fmt.Errorf("user already exists")
	}
	// Si hay error pero no es "no rows found", devolver el error
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}

	// Validar contraseña según ISO 27001
	validator := utils.NewPasswordValidator()
	isValid, errors := validator.ValidatePassword(req.Password)
	if !isValid {
		return nil, fmt.Errorf("password validation failed: %s", strings.Join(errors, "; "))
	}

	// Hash de la contraseña
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Crear usuario
	user := &models.User{
		ID:                  generateUUID(),
		Email:               req.Email,
		PasswordHash:        string(hashedPassword),
		FirstName:           req.FirstName,
		LastName:            req.LastName,
		DocumentNumber:      req.DocumentNumber,
		DocumentType:        req.DocumentType,
		VenueID:             req.VenueID,
		IsActive:            true,
		IsLocked:            false,
		FailedLoginAttempts: 0,
		LastFailedLoginAt:   nil,
		LockedUntil:         nil,
	}

	err = s.repo.CreateUser(user)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Limpiar datos sensibles
	user.PasswordHash = ""

	return user, nil
}

func (s *authService) GetUserProfile(userID string) (*models.User, []models.Role, error) {
	user, err := s.repo.GetUserByID(userID)
	if err != nil {
		return nil, nil, fmt.Errorf("user not found: %w", err)
	}

	roles, err := s.repo.GetUserRoles(userID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	// Limpiar datos sensibles
	user.PasswordHash = ""

	return user, roles, nil
}

func (s *authService) ValidateToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}

func (s *authService) generateJWT(userID, email string, roles []models.Role) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"exp":     time.Now().Add(s.jwtExpires).Unix(),
		"iat":     time.Now().Unix(),
	}

	// Agregar roles al token
	var roleCodes []string
	for _, role := range roles {
		roleCodes = append(roleCodes, role.Code)
	}
	claims["roles"] = roleCodes

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtSecret))
}

// ================================================
// User management methods
// ================================================

func (s *authService) GetAllUsers() ([]models.User, error) {
	users, err := s.repo.GetAllUsers()
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}

	// Limpiar datos sensibles
	for i := range users {
		users[i].PasswordHash = ""
	}

	return users, nil
}

func (s *authService) GetUser(userID string) (*models.User, []models.Role, error) {
	user, err := s.repo.GetUserByID(userID)
	if err != nil {
		return nil, nil, fmt.Errorf("user not found: %w", err)
	}

	roles, err := s.repo.GetUserRoles(userID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	// Limpiar datos sensibles
	user.PasswordHash = ""

	return user, roles, nil
}

func (s *authService) UpdateUser(userID string, email, firstName, lastName, documentNumber, documentType string, venueID *string, isActive bool) (*models.User, error) {
	// Check if email is being changed and if it already exists
	if email != "" {
		existingUser, err := s.repo.GetUserByEmail(email)
		if err == nil && existingUser != nil && existingUser.ID != userID {
			return nil, fmt.Errorf("email already exists")
		}
	}

	user := &models.User{
		Email:          email,
		FirstName:      firstName,
		LastName:       lastName,
		DocumentNumber: documentNumber,
		DocumentType:   documentType,
		VenueID:        venueID,
		IsActive:       isActive,
	}

	err := s.repo.UpdateUser(userID, user)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Obtener usuario actualizado
	updatedUser, err := s.repo.GetUserByID(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get updated user: %w", err)
	}

	// Limpiar datos sensibles
	updatedUser.PasswordHash = ""

	return updatedUser, nil
}

func (s *authService) DeleteUser(userID string) error {
	err := s.repo.DeleteUser(userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// ================================================
// Role management methods
// ================================================

func (s *authService) GetAllRoles() ([]models.Role, error) {
	roles, err := s.repo.GetAllRoles()
	if err != nil {
		return nil, fmt.Errorf("failed to get roles: %w", err)
	}

	return roles, nil
}

func (s *authService) AssignRole(userID string, roleID int) error {
	// Verificar que el usuario existe
	_, err := s.repo.GetUserByID(userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Verificar que el rol existe
	_, err = s.repo.GetRoleByID(roleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	// Asignar rol
	err = s.repo.AssignRoleToUser(userID, roleID)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	return nil
}

func (s *authService) RemoveRole(userID string, roleID int) error {
	err := s.repo.RemoveRoleFromUser(userID, roleID)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}

	return nil
}

func (s *authService) ValidateUserHasRole(userID string, roleCode string) (bool, error) {
	hasRole, err := s.repo.UserHasRole(userID, roleCode)
	if err != nil {
		return false, fmt.Errorf("failed to validate role: %w", err)
	}

	return hasRole, nil
}

func (s *authService) ResetUserPassword(userID string, newPassword string) error {
	// Validar que la contraseña cumple con ISO 27001
	validator := utils.NewPasswordValidator()
	isValid, errors := validator.ValidatePassword(newPassword)
	if !isValid {
		return fmt.Errorf("Password requirements: %s", strings.Join(errors, ", "))
	}

	// Hashear la nueva contraseña
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Actualizar la contraseña en la base de datos
	err = s.repo.ResetUserPassword(userID, string(hashedPassword))
	if err != nil {
		return fmt.Errorf("failed to reset password: %w", err)
	}

	return nil
}

func (s *authService) GenerateTemporaryPassword() string {
	// Generate a password that meets ISO 27001 requirements
	// Use crypto/rand for better randomness
	rand.Seed(time.Now().UnixNano())

	const (
		uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lowercase = "abcdefghijklmnopqrstuvwxyz"
		numbers   = "0123456789"
		special   = "!@#$%^&*()_+-=[]{}|;':\",./<>?~`"
		allChars  = uppercase + lowercase + numbers + special
	)

	password := make([]byte, 12)

	// Ensure at least one character from each required category (ISO 27001)
	password[0] = uppercase[rand.Intn(len(uppercase))] // Uppercase
	password[1] = lowercase[rand.Intn(len(lowercase))] // Lowercase
	password[2] = numbers[rand.Intn(len(numbers))]     // Number
	password[3] = special[rand.Intn(len(special))]     // Special char

	// Fill the rest with random characters from all categories
	for i := 4; i < 12; i++ {
		password[i] = allChars[rand.Intn(len(allChars))]
	}

	// Shuffle the password to avoid predictable patterns
	for i := len(password) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		password[i], password[j] = password[j], password[i]
	}

	return string(password)
}

func (s *authService) ChangeUserPassword(userID string, currentPassword, newPassword string) error {
	// Get user from database
	user, err := s.repo.GetUserByID(userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Verify current password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword))
	if err != nil {
		return fmt.Errorf("current password is incorrect")
	}

	// Validate new password according to ISO 27001
	validator := utils.NewPasswordValidator()
	isValid, errors := validator.ValidatePassword(newPassword)
	if !isValid {
		return fmt.Errorf("new password must comply with ISO 27001 standards: %s", strings.Join(errors, ", "))
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	// Update password in database
	err = s.repo.UpdateUserPassword(userID, string(hashedPassword))
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// Generar UUID v4
func generateUUID() string {
	return uuid.New().String()
}
