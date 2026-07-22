package auth

import (
	"context"
	"errors"
	"time"
)

var (
	ErrUserNotFound      = errors.New("Kullanıcı bulunamadı")
	ErrUserAlreadyExists = errors.New("Bu e-posta adresi zaten kayıtlı")
)

type AuthUser struct {
	ID                 string    `json:"id" gorm:"primaryKey"`
	Email              string    `json:"email" gorm:"unique;not null"`
	PasswordHash       string    `json:"-" gorm:"not null"`
	Role               string    `json:"role" gorm:"default:'user'"`
	ResetTokenHash     string    `json:"-"`
	ResetTokenExpireAt time.Time `json:"-"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type UserStore interface {
	Create(ctx context.Context, user *AuthUser) error
	FindByEmail(ctx context.Context, email string) (*AuthUser, error)
	FindByID(ctx context.Context, id string) (*AuthUser, error)
	FindByResetTokenHash(ctx context.Context, tokenHash string) (*AuthUser, error)
	UpdateResetToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error
	UpdatePassword(ctx context.Context, userID, newPasswordHash string) error
}
