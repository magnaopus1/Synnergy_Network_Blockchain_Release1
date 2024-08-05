package channel_core

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/scrypt"
)

// Channel represents a payment channel in the network.
type Channel struct {
    ID          string
    Balance     uint64
    Participants []string
    CreatedAt   time.Time
    UpdatedAt   time.Time
}

// ChannelManager manages all the channels in the network.
type ChannelManager struct {
    channels map[string]*Channel
    mu       sync.RWMutex
}

// NewChannelManager creates a new ChannelManager.
func NewChannelManager() *ChannelManager {
    return &ChannelManager{
        channels: make(map[string]*Channel),
    }
}

// CreateChannel creates a new channel with the given participants.
func (cm *ChannelManager) CreateChannel(participants []string) (string, error) {
    cm.mu.Lock()
    defer cm.mu.Unlock()

    id, err := generateChannelID()
    if err != nil {
        return "", err
    }

    channel := &Channel{
        ID:          id,
        Balance:     0,
        Participants: participants,
        CreatedAt:   time.Now(),
        UpdatedAt:   time.Now(),
    }

    cm.channels[id] = channel
    return id, nil
}

// GetChannel retrieves a channel by its ID.
func (cm *ChannelManager) GetChannel(id string) (*Channel, error) {
    cm.mu.RLock()
    defer cm.mu.RUnlock()

    channel, exists := cm.channels[id]
    if !exists {
        return nil, errors.New("channel not found")
    }

    return channel, nil
}

// UpdateChannelBalance updates the balance of a channel.
func (cm *ChannelManager) UpdateChannelBalance(id string, balance uint64) error {
    cm.mu.Lock()
    defer cm.mu.Unlock()

    channel, exists := cm.channels[id]
    if !exists {
        return errors.New("channel not found")
    }

    channel.Balance = balance
    channel.UpdatedAt = time.Now()
    return nil
}

// CloseChannel closes a channel by its ID.
func (cm *ChannelManager) CloseChannel(id string) error {
    cm.mu.Lock()
    defer cm.mu.Unlock()

    _, exists := cm.channels[id]
    if !exists {
        return errors.New("channel not found")
    }

    delete(cm.channels, id)
    return nil
}

// generateChannelID generates a secure, unique ID for a new channel.
func generateChannelID() (string, error) {
    // Generate a random 256-bit (32-byte) value.
    randomBytes := make([]byte, 32)
    _, err := rand.Read(randomBytes)
    if err != nil {
        return "", err
    }

    // Use SHA-256 to hash the random value, ensuring a uniform length.
    hash := sha256.Sum256(randomBytes)
    return hex.EncodeToString(hash[:]), nil
}

// ScryptHashPassword hashes a password using the Scrypt algorithm.
func ScryptHashPassword(password, salt []byte) ([]byte, error) {
    const N = 1 << 15
    const r = 8
    const p = 1
    const keyLen = 32

    hash, err := scrypt.Key(password, salt, N, r, p, keyLen)
    if err != nil {
        return nil, err
    }
    return hash, nil
}

// Argon2HashPassword hashes a password using the Argon2 algorithm.
func Argon2HashPassword(password, salt []byte) []byte {
    const time = 1
    const memory = 64 * 1024
    const threads = 4
    const keyLen = 32

    hash := argon2.IDKey(password, salt, time, memory, threads, keyLen)
    return hash
}

// Securely compare two hashed passwords to avoid timing attacks.
func SecureCompare(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    result := 0
    for i := 0; i < len(a); i++ {
        result |= int(a[i] ^ b[i])
    }
    return result == 0
}

// Argon2IDKey derives a key using the Argon2id algorithm, which is a hybrid of Argon2i and Argon2d.
func Argon2IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
    return argon2.IDKey(password, salt, time, memory, threads, keyLen)
}

// ScryptKey derives a key using the Scrypt algorithm.
func ScryptKey(password, salt []byte, N, r, p, keyLen int) ([]byte, error) {
    return scrypt.Key(password, salt, N, r, p, keyLen)
}

// Example usage of ScryptKey
func ExampleScryptKey() {
    password := []byte("example_password")
    salt := make([]byte, 32)
    if _, err := rand.Read(salt); err != nil {
        panic(err)
    }

    hash, err := ScryptKey(password, salt, 1<<15, 8, 1, 32)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Scrypt hash: %x\n", hash)
}

// Example usage of Argon2IDKey
func ExampleArgon2IDKey() {
    password := []byte("example_password")
    salt := make([]byte, 32)
    if _, err := rand.Read(salt); err != nil {
        panic(err)
    }

    hash := Argon2IDKey(password, salt, 1, 64*1024, 4, 32)
    fmt.Printf("Argon2ID hash: %x\n", hash)
}
