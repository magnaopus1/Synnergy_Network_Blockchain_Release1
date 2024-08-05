package data_channels

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

// DataChannel represents a channel for data transactions
type DataChannel struct {
	ChannelID      string
	ParticipantIDs []string
	Data           []byte
	Signatures     map[string][]byte
	Timestamp      time.Time
	Status         string
	lock           sync.RWMutex
}

const (
	DataActive   = "ACTIVE"
	DataInactive = "INACTIVE"
	DataClosed   = "CLOSED"
)

// NewDataChannel initializes a new data channel
func NewDataChannel(channelID string, participantIDs []string, initialData []byte) *DataChannel {
	return &DataChannel{
		ChannelID:      channelID,
		ParticipantIDs: participantIDs,
		Data:           initialData,
		Signatures:     make(map[string][]byte),
		Timestamp:      time.Now(),
		Status:         DataActive,
	}
}

// UpdateData updates the data in the channel
func (dc *DataChannel) UpdateData(newData []byte, participantID string, signature []byte) error {
	dc.lock.Lock()
	defer dc.lock.Unlock()

	if dc.Status != DataActive {
		return errors.New("cannot update data in an inactive or closed channel")
	}

	dc.Data = newData
	dc.Signatures[participantID] = signature
	dc.Timestamp = time.Now()
	return nil
}

// CloseChannel closes the data channel
func (dc *DataChannel) CloseChannel(finalData []byte, participantID string, signature []byte) error {
	dc.lock.Lock()
	defer dc.lock.Unlock()

	if dc.Status != DataActive {
		return errors.New("channel is not active")
	}

	dc.Data = finalData
	dc.Signatures[participantID] = signature
	dc.Timestamp = time.Now()
	dc.Status = DataClosed
	return nil
}

// VerifySignatures verifies the signatures of all participants
func (dc *DataChannel) VerifySignatures() error {
	dc.lock.RLock()
	defer dc.lock.RUnlock()

	for _, participantID := range dc.ParticipantIDs {
		signature, exists := dc.Signatures[participantID]
		if !exists {
			return fmt.Errorf("missing signature from participant %s", participantID)
		}

		if !utils.VerifySignature(dc.Data, signature, participantID) {
			return fmt.Errorf("invalid signature from participant %s", participantID)
		}
	}

	return nil
}

// EncryptData encrypts the data in the channel
func (dc *DataChannel) EncryptData(key []byte) (string, error) {
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

	ciphertext := gcm.Seal(nonce, nonce, dc.Data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts the encrypted data in the channel
func (dc *DataChannel) DecryptData(encryptedData string, key []byte) error {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
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
	data, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	dc.Data = data
	return nil
}

// GenerateKey generates a cryptographic key using Argon2
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

// HashData hashes the data using SHA-256
func HashData(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func (dc *DataChannel) String() string {
	return fmt.Sprintf("ChannelID: %s, Status: %s, Timestamp: %s", dc.ChannelID, dc.Status, dc.Timestamp)
}

// ValidateData performs validation on the data channel's state
func (dc *DataChannel) ValidateData() error {
	dc.lock.RLock()
	defer dc.lock.RUnlock()

	if len(dc.Data) == 0 {
		return errors.New("data cannot be empty")
	}

	for _, participantID := range dc.ParticipantIDs {
		if _, exists := dc.Signatures[participantID]; !exists {
			return fmt.Errorf("missing signature from participant %s", participantID)
		}
	}

	return nil
}

// AddParticipant adds a new participant to the data channel
func (dc *DataChannel) AddParticipant(participantID string) error {
	dc.lock.Lock()
	defer dc.lock.Unlock()

	for _, id := range dc.ParticipantIDs {
		if id == participantID {
			return errors.New("participant already exists")
		}
	}

	dc.ParticipantIDs = append(dc.ParticipantIDs, participantID)
	return nil
}

// RemoveParticipant removes a participant from the data channel
func (dc *DataChannel) RemoveParticipant(participantID string) error {
	dc.lock.Lock()
	defer dc.lock.Unlock()

	for i, id := range dc.ParticipantIDs {
		if id == participantID {
			dc.ParticipantIDs = append(dc.ParticipantIDs[:i], dc.ParticipantIDs[i+1:]...)
			delete(dc.Signatures, participantID)
			return nil
		}
	}

	return errors.New("participant not found")
}

// GetParticipantIDs returns the list of participant IDs in the data channel
func (dc *DataChannel) GetParticipantIDs() []string {
	dc.lock.RLock()
	defer dc.lock.RUnlock()
	return dc.ParticipantIDs
}

// GetData returns the data in the channel
func (dc *DataChannel) GetData() []byte {
	dc.lock.RLock()
	defer dc.lock.RUnlock()
	return dc.Data
}

// GetStatus returns the current status of the data channel
func (dc *DataChannel) GetStatus() string {
	dc.lock.RLock()
	defer dc.lock.RUnlock()
	return dc.Status
}

// IsActive checks if the data channel is active
func (dc *DataChannel) IsActive() bool {
	dc.lock.RLock()
	defer dc.lock.RUnlock()
	return dc.Status == DataActive
}

// IsClosed checks if the data channel is closed
func (dc *DataChannel) IsClosed() bool {
	dc.lock.RLock()
	defer dc.lock.RUnlock()
	return dc.Status == DataClosed
}

// EncryptAndSignData encrypts the data and signs it with the given participant's ID
func (dc *DataChannel) EncryptAndSignData(key, data []byte, participantID string) (string, error) {
	encryptedData, err := dc.EncryptData(key)
	if err != nil {
		return "", err
	}
	signature := utils.SignData(encryptedData, participantID)
	dc.Signatures[participantID] = signature
	return encryptedData, nil
}

// DecryptAndVerifyData decrypts the data and verifies the signature with the given participant's ID
func (dc *DataChannel) DecryptAndVerifyData(encryptedData string, key []byte, participantID string) ([]byte, error) {
	err := dc.DecryptData(encryptedData, key)
	if err != nil {
		return nil, err
	}
	signature, exists := dc.Signatures[participantID]
	if !exists {
		return nil, errors.New("signature not found for participant")
	}
	if !utils.VerifySignature(dc.Data, signature, participantID) {
		return nil, errors.New("invalid signature for participant")
	}
	return dc.Data, nil
}

// UpdateTimestamp updates the timestamp of the data channel
func (dc *DataChannel) UpdateTimestamp() {
	dc.lock.Lock()
	defer dc.lock.Unlock()
	dc.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the data channel
func (dc *DataChannel) GetTimestamp() time.Time {
	dc.lock.RLock()
	defer dc.lock.RUnlock()
	return dc.Timestamp
}
