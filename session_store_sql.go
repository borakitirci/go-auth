package auth

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
)

type SQLSessionStore struct {
	db         *sql.DB
	driverType DriverType
}

func NewSQLSessionStore(db *sql.DB, driverType DriverType) *SQLSessionStore {
	return &SQLSessionStore{
		db:         db,
		driverType: driverType,
	}
}

func (s *SQLSessionStore) P(index int) string {
	if s.driverType == DriverPostgres {
		return "$" + strconv.Itoa(index)
	}
	return "?"
}

func (s *SQLSessionStore) AutoMigrate(ctx context.Context) error {
	var query string

	switch s.driverType {
	case DriverPostgres:
		query = `
		CREATE TABLE IF NOT EXISTS auth_sessions (
			id VARCHAR(64) PRIMARY KEY,
			user_id VARCHAR(36) NOT NULL,
			refresh_token_hash VARCHAR(255) NOT NULL,
			device VARCHAR(255),
			ip_address VARCHAR(45),
			user_agent TEXT,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL
		);`
	default:
		return fmt.Errorf("desteklenmeyen veritabanı sürücüsü: %s", s.driverType)
	}

	_, err := s.db.ExecContext(ctx, query)
	return err
}

func (s *SQLSessionStore) SaveSession(ctx context.Context, session *SessionMetadata) error {
	query := fmt.Sprintf(`
		INSERT INTO auth_sessions (id, user_id, refresh_token_hash, device, ip_address, user_agent, expires_at, created_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s)`,
		s.P(1), s.P(2), s.P(3), s.P(4), s.P(5), s.P(6), s.P(7), s.P(8),
	)

	_, err := s.db.ExecContext(ctx, query,
		session.ID,
		session.UserID,
		session.RefreshTokenHash,
		session.Device,
		session.IPAddress,
		session.UserAgent,
		session.ExpiresAt,
		session.CreatedAt,
	)
	return err
}

func (s *SQLSessionStore) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*SessionMetadata, error) {
	query := fmt.Sprintf(`
		SELECT id, user_id, refresh_token_hash, device, ip_address, user_agent, expires_at, created_at
		FROM auth_sessions WHERE refresh_token_hash = %s`,
		s.P(1),
	)

	var sess SessionMetadata
	err := s.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&sess.ID,
		&sess.UserID,
		&sess.RefreshTokenHash,
		&sess.Device,
		&sess.IPAddress,
		&sess.UserAgent,
		&sess.ExpiresAt,
		&sess.CreatedAt,
	)

	if err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *SQLSessionStore) RevokeSession(ctx context.Context, userID, tokenHash string) error {
	query := fmt.Sprintf(`DELETE FROM auth_sessions WHERE user_id = %s AND refresh_token_hash = %s`, s.P(1), s.P(2))
	_, err := s.db.ExecContext(ctx, query, userID, tokenHash)
	return err
}

func (s *SQLSessionStore) RevokeAllUserSessions(ctx context.Context, userID string) error {
	query := fmt.Sprintf(`DELETE FROM auth_sessions WHERE user_id = %s`, s.P(1))
	_, err := s.db.ExecContext(ctx, query, userID)
	return err
}
