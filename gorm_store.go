package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
)

type GORMStore struct {
	db *gorm.DB
}

func NewGORMStore(db *gorm.DB) *GORMStore {
	return &GORMStore{db: db}
}

func (s *GORMStore) Migrate() error {
	return s.db.AutoMigrate(&AuthUser{})
}

func (s *GORMStore) Create(ctx context.Context, user *AuthUser) error {
	err := s.db.WithContext(ctx).Create(user).Error

	if err != nil {
		errStr := err.Error()
		if errors.Is(err, gorm.ErrDuplicatedKey) || strings.Contains(errStr, "duplicate key") || strings.Contains(errStr, "duplicate entry") || strings.Contains(errStr, "UNIQUE constraint failed") {
			return ErrUserAlreadyExists
		}
		return err
	}

	return nil
}

func (s *GORMStore) FindByEmail(ctx context.Context, email string) (*AuthUser, error) {
	var user AuthUser
	err := s.db.WithContext(ctx).Where("email = ?", email).First(&user).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}

	return &user, err
}

func (s *GORMStore) FindByID(ctx context.Context, id string) (*AuthUser, error) {
	var user AuthUser
	err := s.db.WithContext(ctx).Where("id = ?", id).First(&user).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}

	return &user, err
}

func (s *GORMStore) FindByResetTokenHash(ctx context.Context, tokenHash string) (*AuthUser, error) {
	var user AuthUser
	err := s.db.WithContext(ctx).Where("reset_token_hash = ? AND reset_token_expire_at > ?", tokenHash, time.Now()).First(&user).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}

	return &user, err
}

func (s *GORMStore) UpdateResetToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	return s.db.WithContext(ctx).Model(&AuthUser{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"reset_token_hash":      tokenHash,
		"reset_token_expire_at": expiresAt,
	}).Error
}

func (s *GORMStore) UpdatePassword(ctx context.Context, userID, newPasswordHash string) error {
	return s.db.WithContext(ctx).Model(&AuthUser{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"password_hash":         newPasswordHash,
		"reset_token_hash":      "",
		"reset_token_expire_at": time.Time{},
	}).Error
}
