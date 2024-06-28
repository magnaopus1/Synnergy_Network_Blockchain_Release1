package authentication

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/go-redis/redis/v8"
	"golang.org/x/crypto/bcrypt"
	"synnergy_network_blockchain/pkg/synnergy_network/core/wallet/utils"
)

// SessionManager handles the session management
type SessionManager struct {
	redisClient *redis.Client
	ctx         context.Context
}

// NewSessionManager creates a new session manager
func NewSessionManager(redisAddr string) *SessionManager {
	rdb := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})
	return &SessionManager{
		redisClient: rdb,
		ctx:         context.Background(),
	}
}

// CreateSession creates a new session for a user
func (sm *SessionManager) CreateSession(userID string, sessionDuration time.Duration) (string, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return "", err
	}

	sessionKey := sm.getSessionKey(sessionID)
	hashedUserID, err := bcrypt.GenerateFromPassword([]byte(userID), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	err = sm.redisClient.Set(sm.ctx, sessionKey, hashedUserID, sessionDuration).Err()
	if err != nil {
		return "", err
	}

	return sessionID, nil
}

// ValidateSession checks if the session is valid
func (sm *SessionManager) ValidateSession(sessionID, userID string) (bool, error) {
	sessionKey := sm.getSessionKey(sessionID)
	storedHashedUserID, err := sm.redisClient.Get(sm.ctx, sessionKey).Result()
	if err != nil {
		if err == redis.Nil {
			return false, errors.New("session not found")
		}
		return false, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHashedUserID), []byte(userID))
	if err != nil {
		return false, errors.New("invalid session")
	}

	return true, nil
}

// InvalidateSession invalidates a given session
func (sm *SessionManager) InvalidateSession(sessionID string) error {
	sessionKey := sm.getSessionKey(sessionID)
	err := sm.redisClient.Del(sm.ctx, sessionKey).Err()
	if err != nil {
		return err
	}
	return nil
}

// RefreshSession refreshes the session expiry time
func (sm *SessionManager) RefreshSession(sessionID string, sessionDuration time.Duration) error {
	sessionKey := sm.getSessionKey(sessionID)
	_, err := sm.redisClient.Expire(sm.ctx, sessionKey, sessionDuration).Result()
	if err != nil {
		return err
	}
	return nil
}

// Helper functions

func (sm *SessionManager) getSessionKey(sessionID string) string {
	return "session:" + sessionID
}

func generateSessionID() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

