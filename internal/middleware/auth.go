package middleware

import (
	"net/http"
	"strings"

	"ms-auth-go/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// RequireAuth verifica que el request tenga un token JWT válido
func RequireAuth(authService service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extraer token del header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
			})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Bearer token required",
			})
			c.Abort()
			return
		}

		// Validar token
		token, err := authService.ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
			})
			c.Abort()
			return
		}

		// Extraer claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token claims",
			})
			c.Abort()
			return
		}

		// Guardar user_id en el contexto
		userID, ok := claims["user_id"].(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid user ID in token",
			})
			c.Abort()
			return
		}

		c.Set("user_id", userID)
		c.Set("token_claims", claims)

		c.Next()
	}
}

// RequireRole verifica que el usuario autenticado tenga al menos uno de los roles especificados
func RequireRole(authService service.AuthService, allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Primero verificar autenticación
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			c.Abort()
			return
		}

		userIDStr, ok := userID.(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid user ID",
			})
			c.Abort()
			return
		}

		// Verificar si el usuario tiene alguno de los roles permitidos
		hasRole := false
		for _, role := range allowedRoles {
			authorized, err := authService.ValidateUserHasRole(userIDStr, role)
			if err == nil && authorized {
				hasRole = true
				break
			}
		}

		if !hasRole {
			c.JSON(http.StatusForbidden, gin.H{
				"error":          "Insufficient permissions",
				"required_roles": allowedRoles,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// GetUserIDFromContext obtiene el user_id del contexto
func GetUserIDFromContext(c *gin.Context) (string, bool) {
	userID, exists := c.Get("user_id")
	if !exists {
		return "", false
	}

	userIDStr, ok := userID.(string)
	return userIDStr, ok
}
