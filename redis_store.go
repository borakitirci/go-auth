package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisStore struct {
	client *redis.Client
}

func NewRedisStore(client *redis.Client) *RedisStore {
	return &RedisStore{client: client}
}

func (r *RedisStore) SaveSession(ctx context.Context, session *SessionMetadata) error {
	data, err := json.Marshal(session)

	if err != nil {
		return err
	}

	ttl := time.Until(session.ExpiresAt)

	if ttl <= 0 {
		return fmt.Errorf("geçersiz süre")
	}

	tokenKey := fmt.Sprintf("auth:refresh:%s", session.RefreshTokenHash)
	if err := r.client.Set(ctx, tokenKey, data, ttl).Err(); err != nil {
		return err
	}

	userSessionsKey := fmt.Sprintf("auth:user:%s:sessions", session.UserID)
	if err := r.client.SAdd(ctx, userSessionsKey, session.RefreshTokenHash).Err(); err != nil {
		return err
	}

	return nil
}

func (r *RedisStore) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*SessionMetadata, error) {
	tokenKey := fmt.Sprintf("auth:refresh:%s", tokenHash)
	val, err := r.client.Get(ctx, tokenKey).Result()

	if err == redis.Nil {
		return nil, fmt.Errorf("oturum süresi dolmuş veya geçersiz")
	} else if err != nil {
		return nil, err
	}

	var session SessionMetadata
	if err := json.Unmarshal([]byte(val), &session); err != nil {
		return nil, err
	}

	return &session, nil
}

func (r *RedisStore) RevokeSession(ctx context.Context, userID, tokenHash string) error {
	tokenKey := fmt.Sprintf("auth:refresh:%s", tokenHash)
	_ = r.client.Del(ctx, tokenKey).Err()

	userSessionsKey := fmt.Sprintf("auth:user:%s:sessions", userID)
	_ = r.client.SRem(ctx, userSessionsKey, tokenHash).Err()

	return nil
}

func (r *RedisStore) RevokeAllUserSessions(ctx context.Context, userID string) error {
	userSessionsKey := fmt.Sprintf("auth:user:%s:sessions", userID)
	hashes, err := r.client.SMembers(ctx, userSessionsKey).Result()

	if err != nil && err != redis.Nil {
		return err
	}

	pipe := r.client.Pipeline()

	for _, h := range hashes {
		tokenKey := fmt.Sprintf("auth:refresh:%s", h)
		pipe.Del(ctx, tokenKey)
	}

	pipe.Del(ctx, userSessionsKey)
	_, err = pipe.Exec(ctx)
	return err
}
