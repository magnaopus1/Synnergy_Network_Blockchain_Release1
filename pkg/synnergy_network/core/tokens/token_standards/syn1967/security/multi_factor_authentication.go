package security

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// MFA defines the Multi-Factor Authentication manager
type MFA struct {
	mu          sync.RWMutex
	userSecrets map[string]string // UserID -> Secret
	userTokens  map[string]string // UserID -> Token
}

// NewMFA creates a new instance of the MFA manager
func NewMFA() *MFA {
	return &MFA{
		userSecrets: make(map[string]string),
		userTokens:  make(map[string]string),
	}
}

// GenerateSecret generates a new secret for a user
func (m *MFA) GenerateSecret(userID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	secret := generateRandomString(32)
	m.userSecrets[userID] = secret

	return secret, nil
}

// ValidateToken validates the provided token for a user
func (m *MFA) ValidateToken(userID, token string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	storedToken, exists := m.userTokens[userID]
	if !exists {
		return false
	}

	return storedToken == token
}

// GenerateToken generates a new token for a user and stores it
func (m *MFA) GenerateToken(userID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	secret, exists := m.userSecrets[userID]
	if !exists {
		return "", errors.New("user does not have a secret generated")
	}

	token := generateRandomString(6)
	m.userTokens[userID] = token

	go m.expireToken(userID, token, secret)

	return token, nil
}

// expireToken invalidates the token after a specified duration
func (m *MFA) expireToken(userID, token, secret string) {
	time.Sleep(5 * time.Minute)

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.userTokens[userID] == token {
		delete(m.userTokens, userID)
	}
}

// generateRandomString generates a random string of the specified length
func generateRandomString(length int) string {
	randBytes := make([]byte, length)
	_, err := rand.Read(randBytes)
	if err != nil {
		panic("failed to generate random bytes")
	}
	return base64.URLEncoding.EncodeToString(randBytes)[:length]
}

// RegisterUser registers a new user with MFA
func (m *MFA) RegisterUser(userID string) (string, error) {
	return m.GenerateSecret(userID)
}

// UnregisterUser removes a user's MFA details
func (m *MFA) UnregisterUser(userID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.userSecrets, userID)
	delete(m.userTokens, userID)
}

// IsRegistered checks if a user is registered for MFA
func (m *MFA) IsRegistered(userID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, exists := m.userSecrets[userID]
	return exists
}

// ValidateAndGenerateToken validates a user's existing token and generates a new one if valid
func (m *MFA) ValidateAndGenerateToken(userID, token string) (string, error) {
	if !m.ValidateToken(userID, token) {
		return "", errors.New("invalid token")
	}

	return m.GenerateToken(userID)
}
