package peg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// User represents a user in the blockchain system.
type User struct {
	Username     string
	PasswordHash string
	Salt         string
	CreatedAt    time.Time
}

// UserManager manages user authentication and related operations.
type UserManager struct {
	mu       sync.Mutex
	users    map[string]*User
	sessions map[string]string // sessionID to username
}

// NewUserManager creates a new instance of UserManager.
func NewUserManager() *UserManager {
	return &UserManager{
		users:    make(map[string]*User),
		sessions: make(map[string]string),
	}
}

// CreateUser creates a new user with the given username and password.
func (um *UserManager) CreateUser(username, password string) error {
	um.mu.Lock()
	defer um.mu.Unlock()

	if _, exists := um.users[username]; exists {
		return errors.New("username already exists")
	}

	salt := generateSalt()
	passwordHash := hashPassword(password, salt)
	user := &User{
		Username:     username,
		PasswordHash: passwordHash,
		Salt:         salt,
		CreatedAt:    time.Now(),
	}
	um.users[username] = user
	return nil
}

// AuthenticateUser authenticates a user with the given username and password.
func (um *UserManager) AuthenticateUser(username, password string) (string, error) {
	um.mu.Lock()
	defer um.mu.Unlock()

	user, exists := um.users[username]
	if !exists {
		return "", errors.New("invalid username or password")
	}

	if !checkPassword(password, user.PasswordHash, user.Salt) {
		return "", errors.New("invalid username or password")
	}

	sessionID := generateSessionID()
	um.sessions[sessionID] = username
	return sessionID, nil
}

// ValidateSession validates a session ID.
func (um *UserManager) ValidateSession(sessionID string) (string, error) {
	um.mu.Lock()
	defer um.mu.Unlock()

	username, exists := um.sessions[sessionID]
	if !exists {
		return "", errors.New("invalid session")
	}
	return username, nil
}

// InvalidateSession invalidates a session ID.
func (um *UserManager) InvalidateSession(sessionID string) {
	um.mu.Lock()
	defer um.mu.Unlock()

	delete(um.sessions, sessionID)
}

// hashPassword hashes a password using Argon2.
func hashPassword(password, salt string) string {
	hash := argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}

// checkPassword checks if the password matches the hashed password.
func checkPassword(password, hash, salt string) bool {
	expectedHash := hashPassword(password, salt)
	return expectedHash == hash
}

// generateSalt generates a random salt for password hashing.
func generateSalt() string {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic(err)
	}
	return hex.EncodeToString(salt)
}

// generateSessionID generates a random session ID.
func generateSessionID() string {
	sessionID := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, sessionID); err != nil {
		panic(err)
	}
	return hex.EncodeToString(sessionID)
}

// encrypt encrypts plaintext using AES.
func encrypt(plaintext, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

// decrypt decrypts ciphertext using AES.
func decrypt(ciphertext, key string) (string, error) {
	data, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Example implementation of user authentication process
func main() {
	um := NewUserManager()

	// Create a new user
	err := um.CreateUser("alice", "password123")
	if err != nil {
		fmt.Printf("Failed to create user: %v\n", err)
		return
	}

	// Authenticate the user
	sessionID, err := um.AuthenticateUser("alice", "password123")
	if err != nil {
		fmt.Printf("Failed to authenticate user: %v\n", err)
		return
	}

	// Validate the session
	username, err := um.ValidateSession(sessionID)
	if err != nil {
		fmt.Printf("Failed to validate session: %v\n", err)
		return
	}

	fmt.Printf("Session validated for user: %s\n", username)

	// Invalidate the session
	um.InvalidateSession(sessionID)
}
