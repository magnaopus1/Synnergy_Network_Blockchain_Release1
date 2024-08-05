package request_validation

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "golang.org/x/crypto/scrypt"
    "log"
    "time"
)

// User represents a user of the faucet service.
type User struct {
    Username     string
    PasswordHash string
    Salt         string
    LastRequest  time.Time
}

// UserStore is an interface for managing users.
type UserStore interface {
    CreateUser(user *User) error
    GetUser(username string) (*User, error)
    UpdateUser(user *User) error
}

// InMemoryUserStore is an in-memory implementation of UserStore for testing purposes.
type InMemoryUserStore struct {
    users map[string]*User
}

// NewInMemoryUserStore initializes a new InMemoryUserStore.
func NewInMemoryUserStore() *InMemoryUserStore {
    return &InMemoryUserStore{
        users: make(map[string]*User),
    }
}

// CreateUser creates a new user in the store.
func (store *InMemoryUserStore) CreateUser(user *User) error {
    if _, exists := store.users[user.Username]; exists {
        return errors.New("user already exists")
    }
    store.users[user.Username] = user
    return nil
}

// GetUser retrieves a user from the store.
func (store *InMemoryUserStore) GetUser(username string) (*User, error) {
    user, exists := store.users[username]
    if !exists {
        return nil, errors.New("user not found")
    }
    return user, nil
}

// UpdateUser updates an existing user in the store.
func (store *InMemoryUserStore) UpdateUser(user *User) error {
    if _, exists := store.users[user.Username]; !exists {
        return errors.New("user not found")
    }
    store.users[user.Username] = user
    return nil
}

// GenerateSalt generates a new salt for password hashing.
func GenerateSalt() (string, error) {
    salt := make([]byte, 16)
    _, err := rand.Read(salt)
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(salt), nil
}

// HashPassword hashes a password with the given salt using scrypt.
func HashPassword(password, salt string) (string, error) {
    hash, err := scrypt.Key([]byte(password), []byte(salt), 32768, 8, 1, 32)
    if err != nil {
        return "", err
    }
    return hex.EncodeToString(hash), nil
}

// AuthenticateUser authenticates a user based on username and password.
func AuthenticateUser(store UserStore, username, password string) (bool, error) {
    user, err := store.GetUser(username)
    if err != nil {
        return false, err
    }

    hashedPassword, err := HashPassword(password, user.Salt)
    if err != nil {
        return false, err
    }

    if user.PasswordHash != hashedPassword {
        return false, errors.New("invalid password")
    }

    return true, nil
}

// RegisterUser registers a new user with a username and password.
func RegisterUser(store UserStore, username, password string) error {
    salt, err := GenerateSalt()
    if err != nil {
        return err
    }

    hashedPassword, err := HashPassword(password, salt)
    if err != nil {
        return err
    }

    user := &User{
        Username:     username,
        PasswordHash: hashedPassword,
        Salt:         salt,
        LastRequest:  time.Now(),
    }

    return store.CreateUser(user)
}

// UpdateLastRequest updates the last request time for a user.
func UpdateLastRequest(store UserStore, username string) error {
    user, err := store.GetUser(username)
    if err != nil {
        return err
    }

    user.LastRequest = time.Now()
    return store.UpdateUser(user)
}

// Main function for testing
func main() {
    userStore := NewInMemoryUserStore()

    username := "testuser"
    password := "securepassword123"

    // Register a new user
    err := RegisterUser(userStore, username, password)
    if err != nil {
        log.Fatalf("Error registering user: %v", err)
    }
    fmt.Println("User registered successfully")

    // Authenticate the user
    authenticated, err := AuthenticateUser(userStore, username, password)
    if err != nil {
        log.Fatalf("Error authenticating user: %v", err)
    }
    if authenticated {
        fmt.Println("User authenticated successfully")
    } else {
        fmt.Println("User authentication failed")
    }

    // Update last request time
    err = UpdateLastRequest(userStore, username)
    if err != nil {
        log.Fatalf("Error updating last request time: %v", err)
    }
    fmt.Println("Last request time updated successfully")
}
