package auth

import "context"

type SessionStore interface {
	SaveSession(ctx context.Context, session *SessionMetadata) error
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*SessionMetadata, error)
	RevokeSession(ctx context.Context, userID, tokenHash string) error
	RevokeAllUserSessions(ctx context.Context, userID string) error
}
