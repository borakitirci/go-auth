package auth

import "time"

type SessionMetadata struct {
	ID               string    `json:"id"`
	UserID           string    `json:"user_id"`
	RefreshTokenHash string    `json:"-"`
	Device           string    `json:"device"`
	IPAddress        string    `json:"ip_address"`
	UserAgent        string    `json:"user_agent"`
	ExpiresAt        time.Time `json:"expires_at"`
	CreatedAt        time.Time `json:"created_at"`
}
