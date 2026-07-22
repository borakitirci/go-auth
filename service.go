package auth

import (
	"context"
	"errors"
	"time"
)

type Service struct {
	store     UserStore
	jwtSecret string
}

func NewService(store UserStore, jwtSecret string) *Service {
	return &Service{
		store:     store,
		jwtSecret: jwtSecret,
	}
}

func (s *Service) Register(ctx context.Context, id, email, password, role string) (*AuthUser, error) {
	hashedPassword, err := HashPassword(password)

	if err != nil {
		return nil, err
	}

	user := &AuthUser{
		ID:           id,
		Email:        email,
		PasswordHash: hashedPassword,
		Role:         role,
	}

	if err := s.store.Create(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *Service) Login(ctx context.Context, email, password string) (string, error) {
	user, err := s.store.FindByEmail(ctx, email)

	if err != nil {
		return "", ErrUserNotFound
	}

	if !CheckPassword(password, user.PasswordHash) {
		return "", errors.New("Geçersiz şifre")
	}

	return GenerateToken(user.ID, user.Role, s.jwtSecret, time.Hour*24)
}

func (s *Service) ForgotPassword(ctx context.Context, email string) (string, error) {
	user, err := s.store.FindByEmail(ctx, email)

	if err != nil {
		return "", ErrUserNotFound
	}

	token, err := GenerateRandomToken()

	if err != nil {
		return "", err
	}

	tokenHash := HashToken(token)
	expiresAt := time.Now().Add(time.Minute * 15)

	if err := s.store.UpdateResetToken(ctx, user.ID, tokenHash, expiresAt); err != nil {
		return "", err
	}

	return token, nil
}

func (s *Service) ResetPassword(ctx context.Context, token, newPassword string) error {
	tokenHash := HashToken(token)

	user, err := s.store.FindByResetTokenHash(ctx, tokenHash)

	if err != nil {
		return errors.New("Geçersiz veya süresi dolmuş token")
	}

	newHashedPassword, err := HashPassword(newPassword)

	if err != nil {
		return err
	}

	return s.store.UpdatePassword(ctx, user.ID, newHashedPassword)
}
