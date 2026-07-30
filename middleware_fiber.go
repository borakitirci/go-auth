package auth

import (
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
)

const (
	FiberCtxUserIDKey = "auth_user_id"
	FiberCtxRoleKey   = "auth_user_role"
)

func FiberAuthBearer(jwtSecret string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authorization başlığı eksik",
			})
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
				"error": "Geçersiz token formatı (Bearer <token> olmalı)",
			})
		}

		claims, err := ValidateToken(parts[1], jwtSecret)
		if err != nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
				"error": "Geçersiz veya süresi dolmuş token",
			})
		}

		c.Locals(FiberCtxUserIDKey, claims.UserID)
		c.Locals(FiberCtxRoleKey, claims.Role)

		return c.Next()
	}
}

func FiberAuthCookie(jwtSecret string, loginURL string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenStr := c.Cookies("access_token")
		if tokenStr == "" {
			return c.Redirect(loginURL, http.StatusSeeOther)
		}

		claims, err := ValidateToken(tokenStr, jwtSecret)
		if err != nil {
			return c.Redirect(loginURL, http.StatusSeeOther)
		}

		c.Locals(FiberCtxUserIDKey, claims.UserID)
		c.Locals(FiberCtxRoleKey, claims.Role)

		return c.Next()
	}
}

func FiberRequireRole(allowedRoles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		roleVal := c.Locals(FiberCtxRoleKey)
		if roleVal == nil {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{
				"error": "Erişim reddedildi: Rol bilgisi bulunamadı",
			})
		}

		userRole, ok := roleVal.(string)
		if !ok || userRole == "" {
			return c.Status(http.StatusForbidden).JSON(fiber.Map{
				"error": "Erişim reddedildi: Geçersiz rol tipi",
			})
		}

		for _, role := range allowedRoles {
			if userRole == role {
				return c.Next()
			}
		}

		return c.Status(http.StatusForbidden).JSON(fiber.Map{
			"error": "Bu işlem için yetkiniz bulunmuyor",
		})
	}
}

func GetUserIDFromFiber(c *fiber.Ctx) string {
	if id, ok := c.Locals(FiberCtxUserIDKey).(string); ok {
		return id
	}
	return ""
}

func GetUserRoleFromFiber(c *fiber.Ctx) string {
	if role, ok := c.Locals(FiberCtxRoleKey).(string); ok {
		return role
	}
	return ""
}
