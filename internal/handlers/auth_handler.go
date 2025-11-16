package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"ms-auth-go/internal/models"
	"ms-auth-go/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type AuthHandler struct {
	authService service.AuthService
}

func NewAuthHandler(authService service.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Obtener IP del cliente
	ipAddress := c.ClientIP()
	if ipAddress == "" {
		ipAddress = "unknown"
	}

	// Obtener User-Agent
	userAgent := c.GetHeader("User-Agent")
	if userAgent == "" {
		userAgent = "unknown"
	}

	response, err := h.authService.Login(&req, ipAddress, userAgent)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.authService.Register(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, user)
}

func (h *AuthHandler) GetProfile(c *gin.Context) {
	// Extraer token del header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Bearer token required"})
		return
	}

	// Validar token
	token, err := h.authService.ValidateToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Extraer user_id del token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		return
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID in token"})
		return
	}

	// Obtener perfil del usuario
	user, roles, err := h.authService.GetUserProfile(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user":  user,
		"roles": roles,
	})
}

// ================================================
// User management endpoints
// ================================================

func (h *AuthHandler) GetAllUsers(c *gin.Context) {
	users, err := h.authService.GetAllUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, users)
}

func (h *AuthHandler) GetUser(c *gin.Context) {
	userID := c.Param("id")

	user, roles, err := h.authService.GetUser(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user":  user,
		"roles": roles,
	})
}

func (h *AuthHandler) UpdateUser(c *gin.Context) {
	userID := c.Param("id")

	var req struct {
		Email          string  `json:"email" binding:"required,email"`
		FirstName      string  `json:"first_name" binding:"required"`
		LastName       string  `json:"last_name" binding:"required"`
		DocumentNumber string  `json:"document_number" binding:"required"`
		DocumentType   string  `json:"document_type" binding:"required"`
		VenueID        *string `json:"venue_id"`
		IsActive       bool    `json:"is_active"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.authService.UpdateUser(userID, req.Email, req.FirstName, req.LastName, req.DocumentNumber, req.DocumentType, req.VenueID, req.IsActive)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, user)
}

func (h *AuthHandler) DeleteUser(c *gin.Context) {
	userID := c.Param("id")

	err := h.authService.DeleteUser(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deactivated successfully"})
}

// ================================================
// Role management endpoints
// ================================================

func (h *AuthHandler) GetAllRoles(c *gin.Context) {
	roles, err := h.authService.GetAllRoles()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, roles)
}

func (h *AuthHandler) AssignRole(c *gin.Context) {
	userID := c.Param("id")

	var req struct {
		RoleID int `json:"role_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.authService.AssignRole(userID, req.RoleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Role assigned successfully"})
}

func (h *AuthHandler) RemoveRole(c *gin.Context) {
	userID := c.Param("id")
	roleID := c.Param("roleId")

	// Convertir roleID a int
	var roleIDInt int
	if _, err := fmt.Sscanf(roleID, "%d", &roleIDInt); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role ID"})
		return
	}

	err := h.authService.RemoveRole(userID, roleIDInt)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Role removed successfully"})
}

func (h *AuthHandler) ResetPassword(c *gin.Context) {
	userID := c.Param("id")

	var req models.ResetPasswordRequest
	req.UserID = userID

	// Admin must provide the new password
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "New password is required"})
		return
	}

	// Validate that new password is provided
	if req.NewPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "New password cannot be empty"})
		return
	}

	// Reset password with admin-provided password
	err := h.authService.ResetUserPassword(userID, req.NewPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password reset successfully by administrator",
	})
}

// ================================================
// User password change (self-service)
// ================================================

func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get user ID from token
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in token"})
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID type"})
		return
	}

	// Change password
	err := h.authService.ChangeUserPassword(userIDStr, req.CurrentPassword, req.NewPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}
