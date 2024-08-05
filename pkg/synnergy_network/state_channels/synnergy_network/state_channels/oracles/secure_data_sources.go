package oracles

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

// SecureDataSource represents a secure data source for decentralized oracles
type SecureDataSource struct {
	SourceID       string
	Data           map[string]interface{}
	Timestamp      time.Time
	Status         string
	lock           sync.RWMutex
}

const (
	SourceActive   = "ACTIVE"
	SourceInactive = "INACTIVE"
	SourceError    = "ERROR"
)

// NewSecureDataSource initializes a new SecureDataSource instance
func NewSecureDataSource(sourceID string) *SecureDataSource {
	return &SecureDataSource{
		SourceID:  sourceID,
		Data:      make(map[string]interface{}),
		Timestamp: time.Now(),
		Status:    SourceActive,
	}
}

// UpdateData updates the data in the secure data source
func (sds *SecureDataSource) UpdateData(newData map[string]interface{}) error {
	sds.lock.Lock()
	defer sds.lock.Unlock()

	if sds.Status != SourceActive {
		return errors.New("source is not active")
	}

	for key, value := range newData {
		sds.Data[key] = value
	}
	sds.Timestamp = time.Now()
	return nil
}

// DeactivateSource deactivates the secure data source
func (sds *SecureDataSource) DeactivateSource() error {
	sds.lock.Lock()
	defer sds.lock.Unlock()

	if sds.Status != SourceActive {
		return errors.New("source is not active")
	}

	sds.Status = SourceInactive
	sds.Timestamp = time.Now()
	return nil
}

// EncryptSourceData encrypts the secure data source details
func (sds *SecureDataSource) EncryptSourceData(key []byte) (string, error) {
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

	data := fmt.Sprintf("%s|%s|%s",
		sds.SourceID, sds.Data, sds.Status)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptSourceData decrypts the secure data source details
func (sds *SecureDataSource) DecryptSourceData(encryptedData string, key []byte) error {
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

	parts := utils.Split(string(data), '|')
	if len(parts) != 3 {
		return errors.New("invalid encrypted data format")
	}

	sds.SourceID = parts[0]
	sds.Data = utils.ParseData(parts[1])
	sds.Status = parts[2]
	return nil
}

// GetSourceDetails returns the details of the secure data source
func (sds *SecureDataSource) GetSourceDetails() (string, map[string]interface{}, string) {
	sds.lock.RLock()
	defer sds.lock.RUnlock()
	return sds.SourceID, sds.Data, sds.Status
}

// ValidateSource validates the secure data source details
func (sds *SecureDataSource) ValidateSource() error {
	sds.lock.RLock()
	defer sds.lock.RUnlock()

	if sds.SourceID == "" {
		return errors.New("source ID cannot be empty")
	}

	if len(sds.Data) == 0 {
		return errors.New("data cannot be empty")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the secure data source
func (sds *SecureDataSource) UpdateTimestamp() {
	sds.lock.Lock()
	defer sds.lock.Unlock()
	sds.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the secure data source
func (sds *SecureDataSource) GetTimestamp() time.Time {
	sds.lock.RLock()
	defer sds.lock.RUnlock()
	return sds.Timestamp
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

func (sds *SecureDataSource) String() string {
	return fmt.Sprintf("SourceID: %s, Status: %s, Timestamp: %s", sds.SourceID, sds.Status, sds.Timestamp)
}
