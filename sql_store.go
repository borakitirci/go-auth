package auth

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type DriverType string

const (
	DriverPostgres DriverType = "postgres"
	DriverMySQL    DriverType = "mysql"
	DriverSQLite   DriverType = "sqlite"
)

type SQLStore struct {
	db         *sql.DB
	driverType DriverType
}

func NewSQLStore(db *sql.DB, driverType DriverType) *SQLStore {
	return &SQLStore{
		db:         db,
		driverType: driverType,
	}
}

func (s *SQLStore) AutoMigrate(ctx context.Context) error {
	var query string

	switch s.driverType {
	case DriverPostgres:
		query = `
		CREATE TABLE IF NOT EXISTS auth_users (
			id VARCHAR(36) PRIMARY KEY,
			email VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			role VARCHAR(50) NOT NULL DEFAULT 'user',
			reset_token_hash VARCHAR(255),
			reset_token_expire_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);`

	case DriverMySQL:
		query = `
		CREATE TABLE IF NOT EXISTS auth_users (
			id VARCHAR(36) PRIMARY KEY,
			email VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			role VARCHAR(50) NOT NULL DEFAULT 'user',
			reset_token_hash VARCHAR(255),
			reset_token_expire_at DATETIME,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`

	case DriverSQLite:
		query = `
		CREATE TABLE IF NOT EXISTS auth_users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			reset_token_hash TEXT,
			reset_token_expire_at DATETIME,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		);`

	default:
		return fmt.Errorf("desteklenmeyen veritabanı sürücüsü: %s", s.driverType)
	}

	_, err := s.db.ExecContext(ctx, query)
	return err
}

func (s *SQLStore) P(index int) string {
	if s.driverType == DriverPostgres {
		return "$" + strconv.Itoa(index)
	}
	return "?"
}

func (s *SQLStore) Create(ctx context.Context, user *AuthUser) error {
	query := fmt.Sprintf(`
		INSERT INTO auth_users(id, email, password_hash, role, created_at, updated_at)
		VALUES(%s, %s, %s, %s, %s, %s)`,
		s.P(1), s.P(2), s.P(3), s.P(4), s.P(5), s.P(6),
	)

	now := time.Now()
	_, err := s.db.ExecContext(ctx, query, user.ID, user.Email, user.PasswordHash, user.Role, now, now)

	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "duplicate key") || strings.Contains(errStr, "duplicate entry") || strings.Contains(errStr, "UNIQUE constraint failed") {
			return ErrUserAlreadyExists
		}
		return err
	}
	return nil
}

func (s *SQLStore) FindByEmail(ctx context.Context, email string) (*AuthUser, error) {
	query := fmt.Sprintf(`SELECT id, email, password_hash, role, reset_token_hash, reset_token_expire_at, created_at, updated_at FROM auth_users WHERE email = %s`,
		s.P(1),
	)

	var u AuthUser
	var resetHash sql.NullString
	var resetExpire sql.NullTime

	err := s.db.QueryRowContext(ctx, query, email).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Role, &resetHash, &resetExpire, &u.CreatedAt, &u.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}

	if err != nil {
		return nil, err
	}

	if resetHash.Valid {
		u.ResetTokenHash = resetHash.String
	}

	if resetExpire.Valid {
		u.ResetTokenExpireAt = resetExpire.Time
	}

	return &u, nil
}

func (s *SQLStore) FindByID(ctx context.Context, id string) (*AuthUser, error) {
	query := fmt.Sprintf(`SELECT id, email, password_hash, role, created_at, updated_at FROM auth_users WHERE id = %s`,
		s.P(1),
	)

	var u AuthUser
	err := s.db.QueryRowContext(ctx, query, id).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt, &u.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}

	return &u, err
}

func (s *SQLStore) FindByResetTokenHash(ctx context.Context, tokenHash string) (*AuthUser, error) {
	query := fmt.Sprintf(`
		SELECT id, email, password_hash, role, reset_token_hash, reset_token_expire_at 
		FROM auth_users WHERE reset_token_hash = %s AND reset_token_expire_at > %s`,
		s.P(1), s.P(2),
	)

	var u AuthUser
	err := s.db.QueryRowContext(ctx, query, tokenHash, time.Now()).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.ResetTokenHash, &u.ResetTokenExpireAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}

	return &u, err
}

func (s *SQLStore) UpdateResetToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	query := fmt.Sprintf(`UPDATE auth_users SET reset_token_hash = %s, reset_token_expire_at = %s WHERE id = %s`,
		s.P(1), s.P(2), s.P(3),
	)

	_, err := s.db.ExecContext(ctx, query, tokenHash, expiresAt, userID)
	return err
}

func (s *SQLStore) UpdatePassword(ctx context.Context, userID, newPasswordHash string) error {
	query := fmt.Sprintf(`UPDATE auth_users SET password_hash = %s, reset_token_hash = NULL, reset_token_expire_at = NULL WHERE id = %s`,
		s.P(1), s.P(2),
	)

	_, err := s.db.ExecContext(ctx, query, newPasswordHash, userID)
	return err
}
