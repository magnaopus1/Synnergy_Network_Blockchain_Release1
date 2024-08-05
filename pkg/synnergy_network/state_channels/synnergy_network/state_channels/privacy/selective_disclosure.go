package privacy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"github.com/synnergy_network/utils"
)

// SelectiveDisclosure represents selective disclosure settings
type SelectiveDisclosure struct {
	DisclosureID string
	NodeID       string
	Data         string
	Status       string
	Timestamp    time.Time
	lock         sync.RWMutex
}

const (
	DisclosureActive   = "ACTIVE"
	DisclosureInactive = "INACTIVE"
	DisclosureFailed   = "FAILED"
)

// NewSelectiveDisclosure initializes a new SelectiveDisclosure instance
func NewSelectiveDisclosure(disclosureID, nodeID, data string) *SelectiveDisclosure {
	return &SelectiveDisclosure{
		DisclosureID: disclosureID,
		NodeID:       nodeID,
		Data:         data,
		Status:       DisclosureActive,
		Timestamp:    time.Now(),
	}
}

// UpdateDisclosure updates the selective disclosure settings
func (sd *SelectiveDisclosure) UpdateDisclosure(data string) error {
	sd.lock.Lock()
	defer sd.lock.Unlock()

	if sd.Status != DisclosureActive {
		return errors.New("disclosure is not active")
	}

	sd.Data = data
	sd.Timestamp = time.Now()
	return nil
}

// DeactivateDisclosure deactivates the selective disclosure
func (sd *SelectiveDisclosure) DeactivateDisclosure() error {
	sd.lock.Lock()
	defer sd.lock.Unlock()

	if sd.Status != DisclosureActive {
		return errors.New("disclosure is not active")
	}

	sd.Status = DisclosureInactive
	sd.Timestamp = time.Now()
	return nil
}

// ValidateDisclosure validates the disclosure details
func (sd *SelectiveDisclosure) ValidateDisclosure() error {
	sd.lock.RLock()
	defer sd.lock.RUnlock()

	if sd.DisclosureID == "" || sd.NodeID == "" || sd.Data == "" {
		return errors.New("disclosure ID, node ID, and data cannot be empty")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the disclosure
func (sd *SelectiveDisclosure) UpdateTimestamp() {
	sd.lock.Lock()
	defer sd.lock.Unlock()
	sd.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the disclosure
func (sd *SelectiveDisclosure) GetTimestamp() time.Time {
	sd.lock.RLock()
	defer sd.lock.RUnlock()
	return sd.Timestamp
}

// EncryptDisclosure encrypts the disclosure details
func (sd *SelectiveDisclosure) EncryptDisclosure(key []byte) (string, error) {
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

	data := fmt.Sprintf("%s|%s|%s|%s|%s",
		sd.DisclosureID, sd.NodeID, sd.Data, sd.Status, sd.Timestamp)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptDisclosure decrypts the disclosure details
func (sd *SelectiveDisclosure) DecryptDisclosure(encryptedData string, key []byte) error {
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
	if len(parts) != 5 {
		return errors.New("invalid encrypted data format")
	}

	sd.DisclosureID = parts[0]
	sd.NodeID = parts[1]
	sd.Data = parts[2]
	sd.Status = parts[3]
	sd.Timestamp = utils.ParseTime(parts[4])
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

func (sd *SelectiveDisclosure) String() string {
	return fmt.Sprintf("DisclosureID: %s, Data: %s, Status: %s, Timestamp: %s",
		sd.DisclosureID, sd.Data, sd.Status, sd.Timestamp)
}
