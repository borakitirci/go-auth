package auth

import "context"

type SessionStore interface {
	SaveSession(ctx context.Context, session *SessionMetadata) error
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*SessionMetadata, error)
	GetUserSessions(ctx context.Context, userID string) ([]*SessionMetadata, error)
	GetSessionByID(ctx context.Context, sessionID string) (*SessionMetadata, error)
	RevokeSession(ctx context.Context, userID, tokenHash string) error
	RevokeSessionByID(ctx context.Context, userID, sessionID string) error
	RevokeAllUserSessions(ctx context.Context, userID string) error
}
