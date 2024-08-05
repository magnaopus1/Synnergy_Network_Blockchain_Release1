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

type MultiPartyChannel struct {
    ChannelID      string
    ParticipantIDs []string
    State          []byte
    Signatures     map[string][]byte
    Timestamp      time.Time
    Status         string
    lock           sync.RWMutex
}

const (
    MultiPartyActive   = "ACTIVE"
    MultiPartyInactive = "INACTIVE"
    MultiPartyClosed   = "CLOSED"
)

func NewMultiPartyChannel(channelID string, participantIDs []string, initialState []byte) *MultiPartyChannel {
    return &MultiPartyChannel{
        ChannelID:      channelID,
        ParticipantIDs: participantIDs,
        State:          initialState,
        Signatures:     make(map[string][]byte),
        Timestamp:      time.Now(),
        Status:         MultiPartyActive,
    }
}

func (c *MultiPartyChannel) UpdateState(newState []byte, participantID string, signature []byte) error {
    c.lock.Lock()
    defer c.lock.Unlock()

    if c.Status != MultiPartyActive {
        return errors.New("cannot update state of an inactive or closed channel")
    }

    c.State = newState
    c.Signatures[participantID] = signature
    c.Timestamp = time.Now()
    return nil
}

func (c *MultiPartyChannel) CloseChannel(finalState []byte, participantID string, signature []byte) error {
    c.lock.Lock()
    defer c.lock.Unlock()

    if c.Status != MultiPartyActive {
        return errors.New("channel is not active")
    }

    c.State = finalState
    c.Signatures[participantID] = signature
    c.Timestamp = time.Now()
    c.Status = MultiPartyClosed
    return nil
}

func (c *MultiPartyChannel) VerifySignatures() error {
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

func (c *MultiPartyChannel) EncryptState(key []byte) (string, error) {
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

func (c *MultiPartyChannel) DecryptState(encryptedState string, key []byte) error {
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

func (c *MultiPartyChannel) String() string {
    return fmt.Sprintf("ChannelID: %s, Status: %s, Timestamp: %s", c.ChannelID, c.Status, c.Timestamp)
}

func (c *MultiPartyChannel) ValidateState() error {
    c.lock.RLock()
    defer c.lock.RUnlock()

    if len(c.State) == 0 {
        return errors.New("state cannot be empty")
    }

    for _, participantID := range c.ParticipantIDs {
        if _, exists := c.Signatures[participantID]; !exists {
            return fmt.Errorf("missing signature from participant %s", participantID)
        }
    }

    return nil
}
