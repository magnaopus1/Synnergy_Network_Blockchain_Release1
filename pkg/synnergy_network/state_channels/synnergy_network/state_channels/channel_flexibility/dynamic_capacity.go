package channel_flexibility

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

type DynamicCapacityChannel struct {
    ChannelID      string
    ParticipantIDs []string
    Capacity       int64
    State          []byte
    Signatures     map[string][]byte
    Timestamp      time.Time
    Status         string
    lock           sync.RWMutex
}

const (
    CapacityActive   = "ACTIVE"
    CapacityInactive = "INACTIVE"
    CapacityClosed   = "CLOSED"
)

func NewDynamicCapacityChannel(channelID string, participantIDs []string, initialCapacity int64, initialState []byte) *DynamicCapacityChannel {
    return &DynamicCapacityChannel{
        ChannelID:      channelID,
        ParticipantIDs: participantIDs,
        Capacity:       initialCapacity,
        State:          initialState,
        Signatures:     make(map[string][]byte),
        Timestamp:      time.Now(),
        Status:         CapacityActive,
    }
}

func (c *DynamicCapacityChannel) UpdateCapacity(newCapacity int64, participantID string, signature []byte) error {
    c.lock.Lock()
    defer c.lock.Unlock()

    if c.Status != CapacityActive {
        return errors.New("cannot update capacity of an inactive or closed channel")
    }

    c.Capacity = newCapacity
    c.Signatures[participantID] = signature
    c.Timestamp = time.Now()
    return nil
}

func (c *DynamicCapacityChannel) CloseChannel(finalState []byte, participantID string, signature []byte) error {
    c.lock.Lock()
    defer c.lock.Unlock()

    if c.Status != CapacityActive {
        return errors.New("channel is not active")
    }

    c.State = finalState
    c.Signatures[participantID] = signature
    c.Timestamp = time.Now()
    c.Status = CapacityClosed
    return nil
}

func (c *DynamicCapacityChannel) VerifySignatures() error {
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

func (c *DynamicCapacityChannel) EncryptState(key []byte) (string, error) {
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

func (c *DynamicCapacityChannel) DecryptState(encryptedState string, key []byte) error {
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

func GenerateKey(password, salt []byte) []byte {
    return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

func GenerateSalt() ([]byte, error) {
    salt := make([]byte, 16)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return nil, err
    }
    return salt, nil
}

func HashData(data []byte) []byte {
    hash := sha256.Sum256(data)
    return hash[:]
}

func (c *DynamicCapacityChannel) String() string {
    return fmt.Sprintf("ChannelID: %s, Capacity: %d, Status: %s, Timestamp: %s", c.ChannelID, c.Capacity, c.Status, c.Timestamp)
}

func (c *DynamicCapacityChannel) ValidateCapacity() error {
    c.lock.RLock()
    defer c.lock.RUnlock()

    if c.Capacity <= 0 {
        return errors.New("capacity must be greater than zero")
    }

    for _, participantID := range c.ParticipantIDs {
        if _, exists := c.Signatures[participantID]; !exists {
            return fmt.Errorf("missing signature from participant %s", participantID)
        }
    }

    return nil
}

