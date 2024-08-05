package channel_core

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "time"

    "github.com/synnergy_network/state_channels/channel_core/monitoring"
    "github.com/synnergy_network/state_channels/utils/cryptography"
    "github.com/synnergy_network/state_channels/utils/logging"
)

// ChannelCreationRequest represents the request to create a new state channel.
type ChannelCreationRequest struct {
    ChannelID    string
    Participants []string
    InitialState map[string]interface{}
    Timeout      time.Duration
}

// Channel represents a state channel.
type Channel struct {
    ID           string
    Participants []string
    State        map[string]interface{}
    Timeout      time.Duration
    CreatedAt    time.Time
    UpdatedAt    time.Time
    EncryptionKey []byte
}

// CreateChannel initializes and returns a new state channel.
func CreateChannel(request ChannelCreationRequest) (*Channel, error) {
    if len(request.Participants) < 2 {
        return nil, errors.New("at least two participants are required to create a channel")
    }

    encryptionKey, err := generateEncryptionKey()
    if err != nil {
        return nil, fmt.Errorf("failed to generate encryption key: %v", err)
    }

    channel := &Channel{
        ID:            request.ChannelID,
        Participants:  request.Participants,
        State:         request.InitialState,
        Timeout:       request.Timeout,
        CreatedAt:     time.Now(),
        UpdatedAt:     time.Now(),
        EncryptionKey: encryptionKey,
    }

    // Log channel creation
    logging.Info(fmt.Sprintf("Channel created with ID: %s", channel.ID))

    // Monitor the new channel
    monitoring.StartMonitoring(channel.ID, channel.Timeout)

    return channel, nil
}

// UpdateChannelState updates the state of the channel.
func (c *Channel) UpdateChannelState(newState map[string]interface{}) error {
    c.State = newState
    c.UpdatedAt = time.Now()

    // Log state update
    logging.Info(fmt.Sprintf("Channel state updated for ID: %s", c.ID))

    // Encrypt new state
    encryptedState, err := encryptState(c.State, c.EncryptionKey)
    if err != nil {
        return fmt.Errorf("failed to encrypt state: %v", err)
    }

    // Log encrypted state (for debugging purposes, should be removed in production)
    logging.Debug(fmt.Sprintf("Encrypted state: %s", hex.EncodeToString(encryptedState)))

    return nil
}

// CloseChannel closes the state channel and performs necessary cleanup.
func (c *Channel) CloseChannel() error {
    // Log channel closure
    logging.Info(fmt.Sprintf("Channel closed with ID: %s", c.ID))

    // Stop monitoring the channel
    monitoring.StopMonitoring(c.ID)

    return nil
}

// generateEncryptionKey generates a new encryption key for the channel.
func generateEncryptionKey() ([]byte, error) {
    key := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, key); err != nil {
        return nil, err
    }
    return key, nil
}

// encryptState encrypts the state of the channel using AES.
func encryptState(state map[string]interface{}, key []byte) ([]byte, error) {
    plaintext, err := json.Marshal(state)
    if err != nil {
        return nil, err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    return ciphertext, nil
}

// hashState creates a SHA-256 hash of the state.
func hashState(state map[string]interface{}) (string, error) {
    plaintext, err := json.Marshal(state)
    if err != nil {
        return "", err
    }

    hash := sha256.Sum256(plaintext)
    return hex.EncodeToString(hash[:]), nil
}
