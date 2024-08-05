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

// ChannelIntegration represents the integration of state channels with external systems
type ChannelIntegration struct {
	ChannelID      string
	ParticipantIDs []string
	State          []byte
	Signatures     map[string][]byte
	Timestamp      time.Time
	Status         string
	lock           sync.RWMutex
}

const (
	IntegrationActive   = "ACTIVE"
	IntegrationInactive = "INACTIVE"
	IntegrationClosed   = "CLOSED"
)

// NewChannelIntegration initializes a new channel integration
func NewChannelIntegration(channelID string, participantIDs []string, initialState []byte) *ChannelIntegration {
	return &ChannelIntegration{
		ChannelID:      channelID,
		ParticipantIDs: participantIDs,
		State:          initialState,
		Signatures:     make(map[string][]byte),
		Timestamp:      time.Now(),
		Status:         IntegrationActive,
	}
}

// UpdateState updates the state of the channel integration
func (c *ChannelIntegration) UpdateState(newState []byte, participantID string, signature []byte) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.Status != IntegrationActive {
		return errors.New("cannot update state of an inactive or closed integration")
	}

	c.State = newState
	c.Signatures[participantID] = signature
	c.Timestamp = time.Now()
	return nil
}

// CloseIntegration closes the channel integration and changes its status to closed
func (c *ChannelIntegration) CloseIntegration(finalState []byte, participantID string, signature []byte) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.Status != IntegrationActive {
		return errors.New("integration is not active")
	}

	c.State = finalState
	c.Signatures[participantID] = signature
	c.Timestamp = time.Now()
	c.Status = IntegrationClosed
	return nil
}

// VerifySignatures verifies that all participants have signed the state
func (c *ChannelIntegration) VerifySignatures() error {
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

// EncryptState encrypts the state of the channel integration
func (c *ChannelIntegration) EncryptState(key []byte) (string, error) {
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

// DecryptState decrypts the state of the channel integration
func (c *ChannelIntegration) DecryptState(encryptedState string, key []byte) error {
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

func (c *ChannelIntegration) String() string {
	return fmt.Sprintf("ChannelID: %s, Status: %s, Timestamp: %s", c.ChannelID, c.Status, c.Timestamp)
}

// IntegrationLogic implements the core business logic for the channel integration
func (c *ChannelIntegration) IntegrationLogic(input []byte) ([]byte, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	// Implement the core business logic for the channel integration
	// For example, processing the input data and updating the state
	processedData := processData(input)

	c.State = processedData
	c.Timestamp = time.Now()

	return processedData, nil
}

func processData(input []byte) []byte {
	// Example logic for processing input data
	// In real-world use case, this would be more complex and based on the actual business logic
	hashedInput := sha256.Sum256(input)
	return hashedInput[:]
}

// ValidateIntegration performs validation on the channel integration state
func (c *ChannelIntegration) ValidateIntegration() error {
	c.lock.RLock()
	defer c.lock.RUnlock()

	// Implement validation logic
	// For example, checking the integrity of the state and signatures
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
