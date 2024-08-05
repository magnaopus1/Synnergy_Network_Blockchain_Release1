package resource_security

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "errors"
    "io"
    "sync"
)

// User represents a user in the system with an ID and associated roles
type User struct {
    ID       string
    Roles    []string
    Password string // Stored as a hashed value
}

// AuthService handles user authentication and authorization
type AuthService struct {
    users  map[string]*User
    mu     sync.Mutex
    cipher cipher.Block
}

// NewAuthService initializes the authentication service
func NewAuthService(encryptionKey string) (*AuthService, error) {
    key := sha256.Sum256([]byte(encryptionKey))
    block, err := aes.NewCipher(key[:])
    if err != nil {
        return nil, err
    }

    return &AuthService{
        users:  make(map[string]*User),
        cipher: block,
    }, nil
}

// AddUser adds a new user with a hashed password
func (s *AuthService) AddUser(id, password string, roles []string) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    if _, exists := s.users[id]; exists {
        return errors.New("user already exists")
    }

    hashedPassword, err := s.hashPassword(password)
    if err != nil {
        return err
    }

    s.users[id] = &User{
        ID:       id,
        Password: hashedPassword,
        Roles:    roles,
    }

    return nil
}

// Authenticate verifies a user's credentials
func (s *AuthService) Authenticate(id, password string) (bool, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    user, exists := s.users[id]
    if !exists {
        return false, errors.New("user not found")
    }

    if s.checkPassword(user.Password, password) {
        return true, nil
    }

    return false, errors.New("invalid password")
}

// Authorize checks if a user has a specific role
func (s *AuthService) Authorize(id, role string) (bool, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    user, exists := s.users[id]
    if !exists {
        return false, errors.New("user not found")
    }

    for _, r := range user.Roles {
        if r == role {
            return true, nil
        }
    }

    return false, nil
}

// hashPassword hashes a password using SHA-256 and returns the base64-encoded result
func (s *AuthService) hashPassword(password string) (string, error) {
    hash := sha256.New()
    _, err := hash.Write([]byte(password))
    if err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(hash.Sum(nil)), nil
}

// checkPassword compares a hashed password with a plain password
func (s *AuthService) checkPassword(hashedPassword, plainPassword string) bool {
    hash, _ := s.hashPassword(plainPassword)
    return hashedPassword == hash
}

// EncryptData encrypts data using AES-GCM
func (s *AuthService) EncryptData(plaintext []byte) (string, error) {
    nonce := make([]byte, 12)
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(s.cipher)
    if err != nil {
        return "", err
    }

    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts data using AES-GCM
func (s *AuthService) DecryptData(ciphertext string) ([]byte, error) {
    data, err := base64.StdEncoding.DecodeString(ciphertext)
    if err != nil {
        return nil, err
    }

    nonce := data[:12]
    ciphertext = data[12:]

    gcm, err := cipher.NewGCM(s.cipher)
    if err != nil {
        return nil, err
    }

    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }

    return plaintext, nil
}
