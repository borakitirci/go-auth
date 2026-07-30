package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

type TokenType struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Service struct {
	store        UserStore
	sessionStore SessionStore
	jwtSecret    string
}

func NewService(store UserStore, sessionStore SessionStore, jwtSecret string) *Service {
	return &Service{
		store:        store,
		sessionStore: sessionStore,
		jwtSecret:    jwtSecret,
	}
}

func (s *Service) Register(ctx context.Context, id, email, password, role string) (*AuthUser, error) {
	email = strings.TrimSpace(email)

	if email == "" || !strings.Contains(email, "@") {
		return nil, errors.New("Geçersiz e-posta formatı")
	}

	if len(password) < 8 {
		return nil, errors.New("Şifre en az 8 karakter olmalıdır.")
	}

	existingUser, _ := s.store.FindByEmail(ctx, email)
	if existingUser != nil {
		return nil, ErrUserAlreadyExists
	}

	hashedPassword, err := HashPassword(password)

	if err != nil {
		return nil, err
	}

	if id == "" {
		id = uuid.NewString()
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

func (s *Service) Login(ctx context.Context, email, password string) (*TokenType, error) {
	return s.LoginWithDevice(ctx, email, password, "Unknown Device", "0.0.0.0", "Unknown")
}

func (s *Service) LoginWithDevice(ctx context.Context, email, password, device, ip, userAgent string) (*TokenType, error) {
	user, err := s.store.FindByEmail(ctx, email)

	if err != nil {
		return nil, ErrUserNotFound
	}

	if !CheckPassword(password, user.PasswordHash) {
		return nil, errors.New("Geçersiz şifre")
	}

	accessToken, err := GenerateToken(user.ID, user.Role, s.jwtSecret, time.Minute*15)

	if err != nil {
		return nil, err
	}

	refreshTokenStr, err := GenerateRandomToken()

	if err != nil {
		return nil, err
	}

	refreshHash := HashToken(refreshTokenStr)
	session := &SessionMetadata{
		ID:               refreshHash[:16],
		UserID:           user.ID,
		RefreshTokenHash: refreshHash,
		Device:           device,
		IPAddress:        ip,
		UserAgent:        userAgent,
		ExpiresAt:        time.Now().Add(time.Hour * 24 * 30),
		CreatedAt:        time.Now(),
	}

	if err := s.sessionStore.SaveSession(ctx, session); err != nil {
		return nil, err
	}

	return &TokenType{
		AccessToken:  accessToken,
		RefreshToken: refreshTokenStr,
	}, nil
}

func (s *Service) RefreshTokenWithRotation(ctx context.Context, oldRefreshTokenStr string) (*TokenType, error) {
	oldHash := HashToken(oldRefreshTokenStr)
	session, err := s.sessionStore.GetSessionByTokenHash(ctx, oldHash)

	if err != nil {
		return nil, errors.New("geçersiz veya süresi dolmuş oturum")
	}

	_ = s.sessionStore.RevokeSession(ctx, session.UserID, oldHash)
	user, err := s.store.FindByID(ctx, session.UserID)

	if err != nil {
		return nil, ErrUserNotFound
	}

	newAccessToken, err := GenerateToken(user.ID, user.Role, s.jwtSecret, time.Minute*15)
	if err != nil {
		return nil, err
	}

	newRefreshTokenStr, err := GenerateRandomToken()
	if err != nil {
		return nil, err
	}

	newHash := HashToken(newRefreshTokenStr)
	newSession := &SessionMetadata{
		ID:               newHash[:16],
		UserID:           user.ID,
		RefreshTokenHash: newHash,
		Device:           session.Device,
		IPAddress:        session.IPAddress,
		UserAgent:        session.UserAgent,
		ExpiresAt:        time.Now().Add(time.Hour * 24 * 30),
		CreatedAt:        time.Now(),
	}

	if err := s.sessionStore.SaveSession(ctx, newSession); err != nil {
		return nil, err
	}

	return &TokenType{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshTokenStr,
	}, nil
}

func (s *Service) Logout(ctx context.Context, userID, refreshTokenStr string) error {
	hash := HashToken(refreshTokenStr)
	return s.sessionStore.RevokeSession(ctx, userID, hash)
}

func (s *Service) LogoutAll(ctx context.Context, userID string) error {
	return s.sessionStore.RevokeAllUserSessions(ctx, userID)
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

func (s *Service) GetUserSessions(ctx context.Context, userID string) ([]*SessionMetadata, error) {
	return s.sessionStore.GetUserSessions(ctx, userID)
}

func (s *Service) RevokeSessionByID(ctx context.Context, userID, sessionID string) error {
	return s.sessionStore.RevokeSessionByID(ctx, userID, sessionID)
}
