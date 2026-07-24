package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	GinCtxUserIDKey = "auth_user_id"
	GinCtxRoleKey   = "auth_user_role"
)

func GinAuth(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization başlığı eksik"})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Geçersiz token formatı (Bearer <token> olmalı)"})
			return
		}

		claims, err := ValidateToken(parts[1], jwtSecret)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Geçersiz veya süresi dolmuş token"})
			return
		}

		c.Set(GinCtxUserIDKey, claims.UserID)
		c.Set(GinCtxRoleKey, claims.Role)

		c.Next()
	}
}

func GinRequireRole(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleVal, exists := c.Get(GinCtxRoleKey)
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Erişim reddedildi: Rol bilgisi bulunamadı"})
			return
		}

		userRole, ok := roleVal.(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Erişim reddedildi: Geçersiz rol tipi"})
			return
		}

		for _, role := range allowedRoles {
			if userRole == role {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Bu işlem için yetkiniz bulunmuyor"})
	}
}

func GetUserIDFromGin(c *gin.Context) string {
	if id, exists := c.Get(GinCtxUserIDKey); exists {
		if strID, ok := id.(string); ok {
			return strID
		}
	}
	return ""
}

func GetUserRoleFromGin(c *gin.Context) string {
	if role, exists := c.Get(GinCtxRoleKey); exists {
		if strRole, ok := role.(string); ok {
			return strRole
		}
	}
	return ""
}
