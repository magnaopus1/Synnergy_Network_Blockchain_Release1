package authentication

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"golang.org/x/crypto/scrypt"

	"synnergy_network/blockchain/crypto"
	"synnergy_network/core/wallet"
)

// Constants for the middleware configuration.
const (
	keyLength = 32 // Length of the encryption key.
	saltSize  = 16 // Size of the salt.
	nonceSize = 12 // Size for the nonce in AES-GCM.
)

// MiddlewareConfig holds configuration for the AuthMiddleware.
type MiddlewareConfig struct {
	EncryptionKey string
}

// AuthMiddleware handles authentication and session management.
type AuthMiddleware struct {
	config MiddlewareConfig
	aesGCM cipher.AEAD
}

// NewAuthMiddleware initializes and returns an AuthMiddleware with specified configuration.
func NewAuthMiddleware(config MiddlewareConfig) (*AuthMiddleware, error) {
	key, salt, err := generateKey(config.EncryptionKey)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &AuthMiddleware{
		config: config,
		aesGCM: aesGCM,
	}, nil
}

// generateKey uses Scrypt to generate a key from the passphrase.
func generateKey(passphrase string) ([]byte, []byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, keyLength)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

// Middleware function that ensures only authenticated requests are processed.
func (am *AuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !am.isAuthenticated(r) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isAuthenticated checks if the request is authenticated.
func (am *AuthMiddleware) isAuthenticated(r *http.Request) bool {
	token := r.Header.Get("Authorization")
	if token == "" {
		return false
	}

	// Decrypt token logic here, assume token is encrypted using AES-GCM.
	// This is simplified, in real use, ensure to handle errors and edge cases.
	decodedToken, err := hex.DecodeString(token)
	if err != nil {
		return false
	}

	nonce, ciphertext := decodedToken[:nonceSize], decodedToken[nonceSize:]
	plaintext, err := am.aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return false
	}

	// In real implementation, verify the plaintext (e.g., check it against a database or another trusted source).
	return string(plaintext) == "authenticated"
}

// Add any additional functions here to extend the middleware's capabilities, such as logging, token refresh, etc.

