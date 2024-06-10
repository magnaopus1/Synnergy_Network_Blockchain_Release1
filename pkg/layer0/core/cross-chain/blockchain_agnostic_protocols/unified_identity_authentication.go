package crosschain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
)

// UserIdentity represents the standardized identity of a user across different blockchain platforms.
type UserIdentity struct {
	Username string
	PasswordHash string
}

// AuthenticationManager handles the registration and authentication of identities across blockchain ecosystems.
type AuthenticationManager struct {
	users map[string]*UserIdentity
	mu    sync.Mutex
}

// NewAuthenticationManager initializes a new instance of AuthenticationManager.
func NewAuthenticationManager() *AuthenticationManager {
	return &AuthenticationManager{
		users: make(map[string]*UserIdentity),
	}
}

// RegisterUser adds a new user to the system with a username and password.
func (am *AuthenticationManager) RegisterUser(username, password string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if _, exists := am.users[username]; exists {
		return errors.New("user already exists")
	}

	passwordHash := hashPassword(password)
	am.users[username] = &UserIdentity{
		Username: username,
		PasswordHash: passwordHash,
	}

	return nil
}

// AuthenticateUser checks if the username and password combination is correct and returns true if authentication is successful.
func (am *AuthenticationManager) AuthenticateUser(username, password string) bool {
	am.mu.Lock()
	user, exists := am.users[username]
	am.mu.Unlock()

	if !exists {
		return false
	}

	return user.PasswordHash == hashPassword(password)
}

// hashPassword creates a hash of the password using SHA-256 for secure storage and comparison.
func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// Example usage of the AuthenticationManager
func main() {
	authManager := NewAuthenticationManager()
	err := authManager.RegisterUser("user1", "securepassword123")
	if err != nil {
		panic(err)
	}

	// Attempt to authenticate
	isAuthenticated := authManager.AuthenticateUser("user1", "securepassword123")
	if isAuthenticated {
		println("Authentication successful!")
	} else {
		println("Authentication failed!")
	}
}
