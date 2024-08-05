package client

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"

    "golang.org/x/crypto/scrypt"
)

// User represents a user in the blockchain system
type User struct {
    Username   string
    Password   string
    PrivateKey string
    PublicKey  string
    Address    string
    CreatedAt  time.Time
    mu         sync.Mutex
}

// UserManager manages users and their authentication
type UserManager struct {
    users map[string]*User
    mu    sync.Mutex
}

// NewUserManager creates a new UserManager
func NewUserManager() *UserManager {
    return &UserManager{
        users: make(map[string]*User),
    }
}

// RegisterUser registers a new user with a username and password
func (um *UserManager) RegisterUser(username, password string) (*User, error) {
    um.mu.Lock()
    defer um.mu.Unlock()

    if _, exists := um.users[username]; exists {
        return nil, errors.New("username already exists")
    }

    privateKey, publicKey, err := generateKeys(password)
    if err != nil {
        return nil, err
    }

    user := &User{
        Username:   username,
        Password:   hashPassword(password),
        PrivateKey: privateKey,
        PublicKey:  publicKey,
        Address:    publicKey, // Simplified address generation
        CreatedAt:  time.Now(),
    }

    um.users[username] = user
    return user, nil
}

// AuthenticateUser authenticates a user with a username and password
func (um *UserManager) AuthenticateUser(username, password string) (*User, error) {
    um.mu.Lock()
    defer um.mu.Unlock()

    user, exists := um.users[username]
    if !exists {
        return nil, errors.New("user not found")
    }

    if !verifyPassword(password, user.Password) {
        return nil, errors.New("invalid password")
    }

    return user, nil
}

// generateKeys generates a private and public key using scrypt
func generateKeys(password string) (string, string, error) {
    salt := make([]byte, 16)
    if _, err := time.Read(salt); err != nil {
        return "", "", err
    }

    dk, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
    if err != nil {
        return "", "", err
    }

    privateKey := hex.EncodeToString(dk)
    publicKey := hex.EncodeToString(dk[:16]) // Simplified public key generation

    return privateKey, publicKey, nil
}

// hashPassword hashes a password using SHA-256
func hashPassword(password string) string {
    hash := sha256.New()
    hash.Write([]byte(password))
    return hex.EncodeToString(hash.Sum(nil))
}

// verifyPassword verifies a hashed password
func verifyPassword(password, hashedPassword string) bool {
    return hashPassword(password) == hashedPassword
}

// ChangePassword changes a user's password
func (um *UserManager) ChangePassword(username, oldPassword, newPassword string) error {
    um.mu.Lock()
    defer um.mu.Unlock()

    user, exists := um.users[username]
    if !exists {
        return errors.New("user not found")
    }

    if !verifyPassword(oldPassword, user.Password) {
        return errors.New("invalid old password")
    }

    user.Password = hashPassword(newPassword)
    newPrivateKey, newPublicKey, err := generateKeys(newPassword)
    if err != nil {
        return err
    }

    user.PrivateKey = newPrivateKey
    user.PublicKey = newPublicKey
    user.Address = newPublicKey

    return nil
}

// DeleteUser deletes a user from the user manager
func (um *UserManager) DeleteUser(username, password string) error {
    um.mu.Lock()
    defer um.mu.Unlock()

    user, exists := um.users[username]
    if !exists {
        return errors.New("user not found")
    }

    if !verifyPassword(password, user.Password) {
        return errors.New("invalid password")
    }

    delete(um.users, username)
    return nil
}

// ListUsers lists all registered users
func (um *UserManager) ListUsers() []string {
    um.mu.Lock()
    defer um.mu.Unlock()

    var usernames []string
    for username := range um.users {
        usernames = append(usernames, username)
    }
    return usernames
}

// GetUser retrieves a user by username
func (um *UserManager) GetUser(username string) (*User, error) {
    um.mu.Lock()
    defer um.mu.Unlock()

    user, exists := um.users[username]
    if !exists {
        return nil, errors.New("user not found")
    }

    return user, nil
}

// DisplayUserInfo displays information about a user
func (um *UserManager) DisplayUserInfo(username string) error {
    um.mu.Lock()
    defer um.mu.Unlock()

    user, exists := um.users[username]
    if !exists {
        return errors.New("user not found")
    }

    fmt.Printf("User: %s\n", user.Username)
    fmt.Printf("Address: %s\n", user.Address)
    fmt.Printf("Created At: %s\n", user.CreatedAt)
    return nil
}
