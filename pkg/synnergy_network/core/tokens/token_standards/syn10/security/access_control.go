package security

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/core/tokens/syn10/storage"
	"github.com/synnergy_network_blockchain/core/tokens/syn10/utilities"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/aes"
	"golang.org/x/crypto/cipher"
)

// Role defines the various roles in the system with specific permissions.
type Role string

const (
	AdminRole    Role = "admin"
	UserRole     Role = "user"
	IssuerRole   Role = "issuer"
	VerifierRole Role = "verifier"
	AuditorRole  Role = "auditor"
)

// User represents an entity with access to the blockchain.
type User struct {
	ID       string
	Username string
	Email    string
	PasswordHash []byte
	Role     Role
	CreatedAt time.Time
}

// AccessControl manages roles, permissions, and secure access to the system.
type AccessControl struct {
	store storage.Storage
}

// NewAccessControl initializes a new AccessControl instance.
func NewAccessControl(store storage.Storage) *AccessControl {
	return &AccessControl{store: store}
}

// HashPassword hashes the user's password using a secure algorithm.
func (ac *AccessControl) HashPassword(password string) ([]byte, error) {
	salt := utilities.GenerateRandomBytes(16)
	hash, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return append(salt, hash...), nil
}

// VerifyPassword verifies a user's password against the stored hash.
func (ac *AccessControl) VerifyPassword(password string, hash []byte) (bool, error) {
	salt := hash[:16]
	storedHash := hash[16:]
	computedHash, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	if err != nil {
		return false, err
	}
	return utilities.SecureCompare(storedHash, computedHash), nil
}

// AddUser adds a new user to the system with the specified role.
func (ac *AccessControl) AddUser(username, email, password string, role Role) (string, error) {
	userID := utilities.GenerateUUID()
	passwordHash, err := ac.HashPassword(password)
	if err != nil {
		return "", err
	}

	user := User{
		ID:       userID,
		Username: username,
		Email:    email,
		PasswordHash: passwordHash,
		Role:     role,
		CreatedAt: time.Now(),
	}

	err = ac.store.Save(userID, user)
	if err != nil {
		return "", err
	}

	return userID, nil
}

// AuthenticateUser authenticates a user by their username and password.
func (ac *AccessControl) AuthenticateUser(username, password string) (*User, error) {
	userData, err := ac.store.Find("username", username)
	if err != nil || userData == nil {
		return nil, errors.New("user not found")
	}

	user := userData.(User)
	match, err := ac.VerifyPassword(password, user.PasswordHash)
	if err != nil || !match {
		return nil, errors.New("authentication failed")
	}

	return &user, nil
}

// Authorize checks if a user has the necessary permissions for an action.
func (ac *AccessControl) Authorize(userID string, requiredRole Role) (bool, error) {
	userData, err := ac.store.Get(userID)
	if err != nil || userData == nil {
		return false, errors.New("user not found")
	}

	user := userData.(User)
	return user.Role == requiredRole, nil
}

// MultiFactorAuthentication implements an optional layer for security.
func (ac *AccessControl) MultiFactorAuthentication(userID, mfaToken string) (bool, error) {
	// This is a placeholder for actual MFA logic, which could involve TOTP, SMS, etc.
	// For now, assume MFA is passed if the token is "mfa-pass".
	if mfaToken == "mfa-pass" {
		return true, nil
	}
	return false, errors.New("multi-factor authentication failed")
}

// EncryptData encrypts sensitive data using AES with a given key.
func (ac *AccessControl) EncryptData(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := utilities.GenerateRandomBytes(gcm.NonceSize())
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// DecryptData decrypts AES-encrypted data with a given key.
func (ac *AccessControl) DecryptData(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GetUserRole retrieves the role of a user.
func (ac *AccessControl) GetUserRole(userID string) (Role, error) {
	userData, err := ac.store.Get(userID)
	if err != nil || userData == nil {
		return "", errors.New("user not found")
	}

	user := userData.(User)
	return user.Role, nil
}

// SetUserRole sets the role of a user.
func (ac *AccessControl) SetUserRole(userID string, role Role) error {
	userData, err := ac.store.Get(userID)
	if err != nil || userData == nil {
		return errors.New("user not found")
	}

	user := userData.(User)
	user.Role = role

	return ac.store.Save(userID, user)
}
