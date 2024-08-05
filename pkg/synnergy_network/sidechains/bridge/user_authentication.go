package bridge

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "io"
    "sync"
    "time"

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

// User represents a user in the system
type User struct {
    ID       string
    Username string
    Password string
    Salt     []byte
    Created  time.Time
}

// UserAuthenticator handles user authentication
type UserAuthenticator struct {
    mu    sync.Mutex
    users map[string]*User
    aesKey []byte
}

// NewUserAuthenticator creates a new UserAuthenticator
func NewUserAuthenticator(password string, salt []byte) (*UserAuthenticator, error) {
    key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
    if err != nil {
        return nil, err
    }

    return &UserAuthenticator{
        users:  make(map[string]*User),
        aesKey: key,
    }, nil
}

// CreateUser creates a new user with hashed password and salt
func (ua *UserAuthenticator) CreateUser(id, username, password string) error {
    ua.mu.Lock()
    defer ua.mu.Unlock()

    if _, exists := ua.users[username]; exists {
        return errors.New("username already exists")
    }

    salt := make([]byte, 16)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return err
    }

    hashedPassword := hashPassword(password, salt)
    user := &User{
        ID:       id,
        Username: username,
        Password: hashedPassword,
        Salt:     salt,
        Created:  time.Now(),
    }

    ua.users[username] = user
    return nil
}

// AuthenticateUser authenticates a user with username and password
func (ua *UserAuthenticator) AuthenticateUser(username, password string) (bool, error) {
    ua.mu.Lock()
    defer ua.mu.Unlock()

    user, exists := ua.users[username]
    if !exists {
        return false, errors.New("user not found")
    }

    hashedPassword := hashPassword(password, user.Salt)
    if user.Password != hashedPassword {
        return false, errors.New("incorrect password")
    }

    return true, nil
}

// Encrypt encrypts the given plaintext using AES
func (ua *UserAuthenticator) Encrypt(plaintext string) (string, error) {
    block, err := aes.NewCipher(ua.aesKey)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
    return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given ciphertext using AES
func (ua *UserAuthenticator) Decrypt(ciphertext string) (string, error) {
    block, err := aes.NewCipher(ua.aesKey)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    data, err := hex.DecodeString(ciphertext)
    if err != nil {
        return "", err
    }

    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return "", errors.New("invalid ciphertext")
    }

    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }

    return string(plaintext), nil
}

// hashPassword hashes a password using Argon2
func hashPassword(password string, salt []byte) string {
    hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
    return hex.EncodeToString(hash)
}

// GenerateSalt generates a new random salt
func GenerateSalt() ([]byte, error) {
    salt := make([]byte, 16)
    _, err := rand.Read(salt)
    return salt, err
}

// GenerateToken generates a secure token for the user session
func GenerateToken() (string, error) {
    token := make([]byte, 32)
    if _, err := rand.Read(token); err != nil {
        return "", err
    }
    return hex.EncodeToString(token), nil
}

// Example of further utility functions that can be added

// EncryptSensitiveData encrypts sensitive data before storing
func (ua *UserAuthenticator) EncryptSensitiveData(data string) (string, error) {
    return ua.Encrypt(data)
}

// DecryptSensitiveData decrypts sensitive data when retrieving
func (ua *UserAuthenticator) DecryptSensitiveData(data string) (string, error) {
    return ua.Decrypt(data)
}
