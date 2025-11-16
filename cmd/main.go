package main

import (
	"log"
	"os"

	"ms-auth-go/internal/handlers"
	"ms-auth-go/internal/middleware"
	"ms-auth-go/internal/repository"
	"ms-auth-go/internal/service"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

func main() {
	// Configuración
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://bar_user:bar_password@postgres:5432/bar?sslmode=disable"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Repositorio
	repo, err := repository.NewAuthRepository(dbURL)
	if err != nil {
		log.Fatal("Error connecting to database:", err)
	}

	// Servicios
	authService := service.NewAuthService(repo)

	// Handlers
	authHandler := handlers.NewAuthHandler(authService)

	// Router
	router := gin.Default()

	// Middleware CORS básico
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// Rutas públicas
	api := router.Group("/")
	{
		api.POST("/login", authHandler.Login)
		api.POST("/register", authHandler.Register)
		api.GET("/health", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok", "service": "MS-AUTH-BAR"})
		})
	}

	// Rutas protegidas (requieren autenticación)
	protected := router.Group("/")
	protected.Use(middleware.RequireAuth(authService))
	{
		protected.GET("/me", authHandler.GetProfile)
		protected.GET("/roles", authHandler.GetAllRoles)
		// User can change their own password
		protected.POST("/change-password", authHandler.ChangePassword)
	}

	// Rutas de administración (requieren rol admin)
	admin := router.Group("/")
	admin.Use(middleware.RequireAuth(authService))
	admin.Use(middleware.RequireRole(authService, "admin"))
	{
		// User management
		admin.GET("/users", authHandler.GetAllUsers)
		admin.GET("/users/:id", authHandler.GetUser)
		admin.PUT("/users/:id", authHandler.UpdateUser)
		admin.DELETE("/users/:id", authHandler.DeleteUser)

		// Role assignment
		admin.POST("/users/:id/roles", authHandler.AssignRole)
		admin.DELETE("/users/:id/roles/:roleId", authHandler.RemoveRole)

		// Password reset (admin only)
		admin.POST("/users/:id/reset-password", authHandler.ResetPassword)
	}

	log.Printf("MS-AUTH-BAR starting on port %s", port)
	router.Run(":" + port)
}
