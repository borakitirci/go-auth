package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2" // Mock Redis (go get github.com/alicebob/miniredis/v2)
	"github.com/borakitirci/go-auth"
	"github.com/redis/go-redis/v9"
	// "senin-projen/auth" // kendi paket yolun
)

// In-Memory Mock User Store
type MockUserStore struct {
	users map[string]*auth.AuthUser
}

func NewMockUserStore() *MockUserStore {
	return &MockUserStore{users: make(map[string]*auth.AuthUser)}
}

func (m *MockUserStore) Create(ctx context.Context, user *auth.AuthUser) error {
	m.users[user.Email] = user
	return nil
}

func (m *MockUserStore) FindByEmail(ctx context.Context, email string) (*auth.AuthUser, error) {
	u, ok := m.users[email]
	if !ok {
		return nil, auth.ErrUserNotFound
	}
	return u, nil
}

func (m *MockUserStore) FindByID(ctx context.Context, id string) (*auth.AuthUser, error) {
	for _, u := range m.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, auth.ErrUserNotFound
}

func (m *MockUserStore) UpdateResetToken(ctx context.Context, id, tokenHash string, expiresAt time.Time) error {
	return nil
}

func (m *MockUserStore) FindByResetTokenHash(ctx context.Context, tokenHash string) (*auth.AuthUser, error) {
	return nil, nil
}

func (m *MockUserStore) UpdatePassword(ctx context.Context, id, newPasswordHash string) error {
	return nil
}

// ------------------- TEST SENARYOLARI -------------------

func TestRegisterAndLogin(t *testing.T) {
	// 1. Mock Redis Başlat
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Miniredis başlatılamadı: %v", err)
	}
	defer mr.Close()

	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	redisStore := auth.NewRedisStore(redisClient)
	userStore := NewMockUserStore()

	service := auth.NewService(userStore, redisStore, "test-secret-key-123456")
	ctx := context.Background()

	// TEST 1: Başarılı Kayıt
	user, err := service.Register(ctx, "", "test@sanatevi.com", "Sifre1234!", "admin")
	if err != nil {
		t.Fatalf("Kayıt başarısız: %v", err)
	}

	// Değişkeni doğrulayarak "unused variable" hatasını çözüyoruz
	if user.Email != "test@sanatevi.com" {
		t.Errorf("E-posta uyuşmuyor! Gelen: %s", user.Email)
	}

	// TEST 2: Yanlış Şifre ile Giriş (Başarısız Olmalı)
	_, err = service.Login(ctx, "test@sanatevi.com", "YanlisSifre")
	if err == nil {
		t.Errorf("Hatalı şifrede hata dönmesi gerekiyordu ama dönmedi!")
	}

	// TEST 3: Doğru Şifre ile Giriş
	tokens, err := service.Login(ctx, "test@sanatevi.com", "Sifre1234!")
	if err != nil {
		t.Fatalf("Doğru şifre ile giriş yapılamadı: %v", err)
	}

	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Errorf("Tokenlar boş döndü!")
	}
}

func TestTokenRotation(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()

	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	redisStore := auth.NewRedisStore(redisClient)
	userStore := NewMockUserStore()

	service := auth.NewService(userStore, redisStore, "test-secret-key-123456")
	ctx := context.Background()

	// Kullanıcı oluştur ve giriş yap
	service.Register(ctx, "", "rotation@sanatevi.com", "Sifre1234!", "teacher")
	initialTokens, _ := service.Login(ctx, "rotation@sanatevi.com", "Sifre1234!")

	// TEST 1: Refresh Token Yenileme (Rotation)
	newTokens, err := service.RefreshTokenWithRotation(ctx, initialTokens.RefreshToken)
	if err != nil {
		t.Fatalf("Token rotation başarısız: %v", err)
	}

	// TEST 2: Eski Refresh Token Tekrar Kullanılamamalı!
	_, err = service.RefreshTokenWithRotation(ctx, initialTokens.RefreshToken)
	if err == nil {
		t.Errorf("GÜVENLİK AÇIĞI: Eski refresh token tekrar kullanılabildi!")
	}

	// TEST 3: Yeni Refresh Token Geçerli Olmalı
	if newTokens.RefreshToken == initialTokens.RefreshToken {
		t.Errorf("GÜVENLİK AÇIĞI: Yeni refresh token eskisiyle aynı üretildi!")
	}
}
