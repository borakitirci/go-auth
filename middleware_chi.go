package auth

import (
	"context"
	"net/http"
	"strings"
)

type ctxKey string

const (
	ChiUserIDKey ctxKey = "auth_user_id"
	ChiRoleKey   ctxKey = "auth_user_role"
)

func ChiAuthBearer(jwtSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"Authorization başlığı eksik"}`, http.StatusUnauthorized)
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, `{"error":"Geçersiz token formatı"}`, http.StatusUnauthorized)
				return
			}

			claims, err := ValidateToken(parts[1], jwtSecret)
			if err != nil {
				http.Error(w, `{"error":"Geçersiz veya süresi dolmuş token"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), ChiUserIDKey, claims.UserID)
			ctx = context.WithValue(ctx, ChiRoleKey, claims.Role)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func ChiAuthCookie(jwtSecret string, loginURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("access_token")
			if err != nil {
				http.Redirect(w, r, loginURL, http.StatusSeeOther)
				return
			}

			claims, err := ValidateToken(cookie.Value, jwtSecret)
			if err != nil {
				http.Redirect(w, r, loginURL, http.StatusSeeOther)
				return
			}

			ctx := context.WithValue(r.Context(), ChiUserIDKey, claims.UserID)
			ctx = context.WithValue(ctx, ChiRoleKey, claims.Role)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func ChiRequireRole(allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userRole, ok := r.Context().Value(ChiRoleKey).(string)
			if !ok || userRole == "" {
				http.Error(w, `{"error":"Erişim reddedildi: Rol bilgisi bulunamadı"}`, http.StatusForbidden)
				return
			}

			for _, role := range allowedRoles {
				if userRole == role {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, `{"error":"Bu işlem için yetkiniz bulunmuyor"}`, http.StatusForbidden)
		})
	}
}

func GetUserIDFromChi(r *http.Request) string {
	if id, ok := r.Context().Value(ChiUserIDKey).(string); ok {
		return id
	}
	return ""
}

func GetUserRoleFromChi(r *http.Request) string {
	if role, ok := r.Context().Value(ChiRoleKey).(string); ok {
		return role
	}
	return ""
}
