package channel_core

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "errors"
    "fmt"
    "io"
    "sync"
    "time"

    "golang.org/x/crypto/argon2"
    "github.com/synnergy_network/utils"
)

// ChannelState represents the state of a state channel
type ChannelState struct {
    ChannelID      string
    ParticipantIDs []string
    State          []byte
    Signatures     map[string][]byte
    Timestamp      time.Time
    Status         string
    lock           sync.RWMutex
}

const (
    StateActive   = "ACTIVE"
    StateInactive = "INACTIVE"
    StateClosed   = "CLOSED"
)

// NewChannelState initializes a new channel state
func NewChannelState(channelID string, participantIDs []string, initialState []byte) *ChannelState {
    return &ChannelState{
        ChannelID:      channelID,
        ParticipantIDs: participantIDs,
        State:          initialState,
        Signatures:     make(map[string][]byte),
        Timestamp:      time.Now(),
        Status:         StateActive,
    }
}

// UpdateState updates the state of the channel
func (c *ChannelState) UpdateState(newState []byte, participantID string, signature []byte) error {
    c.lock.Lock()
    defer c.lock.Unlock()

    if c.Status != StateActive {
        return errors.New("cannot update state of an inactive or closed channel")
    }

    c.State = newState
    c.Signatures[participantID] = signature
    c.Timestamp = time.Now()
    return nil
}

// CloseChannel closes the channel and changes its status to closed
func (c *ChannelState) CloseChannel(finalState []byte, participantID string, signature []byte) error {
    c.lock.Lock()
    defer c.lock.Unlock()

    if c.Status != StateActive {
        return errors.New("channel is not active")
    }

    c.State = finalState
    c.Signatures[participantID] = signature
    c.Timestamp = time.Now()
    c.Status = StateClosed
    return nil
}

// VerifySignatures verifies that all participants have signed the state
func (c *ChannelState) VerifySignatures() error {
    c.lock.RLock()
    defer c.lock.RUnlock()

    for _, participantID := range c.ParticipantIDs {
        signature, exists := c.Signatures[participantID]
        if !exists {
            return fmt.Errorf("missing signature from participant %s", participantID)
        }

        if !utils.VerifySignature(c.State, signature, participantID) {
            return fmt.Errorf("invalid signature from participant %s", participantID)
        }
    }

    return nil
}

// EncryptState encrypts the state of the channel
func (c *ChannelState) EncryptState(key []byte) (string, error) {
    block, err := aes.NewCipher(key)
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

    ciphertext := gcm.Seal(nonce, nonce, c.State, nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptState decrypts the state of the channel
func (c *ChannelState) DecryptState(encryptedState string, key []byte) error {
    ciphertext, err := base64.StdEncoding.DecodeString(encryptedState)
    if err != nil {
        return err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    state, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return err
    }

    c.State = state
    return nil
}

// GenerateKey generates a secure key using argon2
func GenerateKey(password, salt []byte) []byte {
    return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// GenerateSalt generates a cryptographic salt
func GenerateSalt() ([]byte, error) {
    salt := make([]byte, 16)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return nil, err
    }
    return salt, nil
}

// HashData hashes the given data using SHA-256
func HashData(data []byte) []byte {
    hash := sha256.Sum256(data)
    return hash[:]
}

func (c *ChannelState) String() string {
    return fmt.Sprintf("ChannelID: %s, Status: %s, Timestamp: %s", c.ChannelID, c.Status, c.Timestamp)
}

