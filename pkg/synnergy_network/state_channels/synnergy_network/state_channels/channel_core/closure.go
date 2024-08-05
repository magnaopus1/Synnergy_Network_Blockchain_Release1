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
)

type ChannelClosure struct {
    ChannelID      string
    ParticipantIDs []string
    FinalState     []byte
    Signatures     map[string][]byte
    Timestamp      time.Time
    Status         string
    lock           sync.RWMutex
}

const (
    ClosurePending   = "PENDING"
    ClosureConfirmed = "CONFIRMED"
    ClosureRejected  = "REJECTED"
)

func NewChannelClosure(channelID string, participantIDs []string, finalState []byte) *ChannelClosure {
    return &ChannelClosure{
        ChannelID:      channelID,
        ParticipantIDs: participantIDs,
        FinalState:     finalState,
        Signatures:     make(map[string][]byte),
        Timestamp:      time.Now(),
        Status:         ClosurePending,
    }
}

func (c *ChannelClosure) SignClosure(participantID string, signature []byte) error {
    c.lock.Lock()
    defer c.lock.Unlock()

    if c.Status != ClosurePending {
        return errors.New("cannot sign a non-pending closure")
    }

    c.Signatures[participantID] = signature
    return nil
}

func (c *ChannelClosure) VerifySignatures() error {
    c.lock.RLock()
    defer c.lock.RUnlock()

    for _, participantID := range c.ParticipantIDs {
        signature, exists := c.Signatures[participantID]
        if !exists {
            return fmt.Errorf("missing signature from participant %s", participantID)
        }

        if !verifySignature(c.FinalState, signature, participantID) {
            return fmt.Errorf("invalid signature from participant %s", participantID)
        }
    }

    c.Status = ClosureConfirmed
    return nil
}

func (c *ChannelClosure) RejectClosure(reason string) {
    c.lock.Lock()
    defer c.lock.Unlock()

    c.Status = ClosureRejected
    // Log the reason for rejection for further analysis
    logRejection(c.ChannelID, reason)
}

func verifySignature(data, signature []byte, participantID string) bool {
    // Implement your signature verification logic here
    // This is a placeholder implementation
    return true
}

func logRejection(channelID, reason string) {
    // Implement logging logic here
    fmt.Printf("Channel %s closure rejected: %s\n", channelID, reason)
}

func (c *ChannelClosure) EncryptFinalState(key []byte) (string, error) {
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

    ciphertext := gcm.Seal(nonce, nonce, c.FinalState, nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (c *ChannelClosure) DecryptFinalState(encryptedFinalState string, key []byte) error {
    ciphertext, err := base64.StdEncoding.DecodeString(encryptedFinalState)
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
    finalState, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return err
    }

    c.FinalState = finalState
    return nil
}

func generateKey(password, salt []byte) []byte {
    return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

func generateSalt() ([]byte, error) {
    salt := make([]byte, 16)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return nil, err
    }
    return salt, nil
}

func hashData(data []byte) []byte {
    hash := sha256.Sum256(data)
    return hash[:]
}
