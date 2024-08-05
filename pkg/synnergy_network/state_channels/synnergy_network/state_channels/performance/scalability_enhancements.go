package performance

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"github.com/synnergy_network/utils"
)

// ScalabilityEnhancement represents the scalability enhancement settings
type ScalabilityEnhancement struct {
	EnhancementID string
	NodeID        string
	ScalingFactor int64
	Status        string
	Timestamp     time.Time
	lock          sync.RWMutex
}

const (
	EnhancementActive   = "ACTIVE"
	EnhancementInactive = "INACTIVE"
	EnhancementFailed   = "FAILED"
)

// NewScalabilityEnhancement initializes a new ScalabilityEnhancement instance
func NewScalabilityEnhancement(enhancementID, nodeID string, scalingFactor int64) *ScalabilityEnhancement {
	return &ScalabilityEnhancement{
		EnhancementID: enhancementID,
		NodeID:        nodeID,
		ScalingFactor: scalingFactor,
		Status:        EnhancementActive,
		Timestamp:     time.Now(),
	}
}

// UpdateEnhancement updates the scalability enhancement settings
func (se *ScalabilityEnhancement) UpdateEnhancement(scalingFactor int64) error {
	se.lock.Lock()
	defer se.lock.Unlock()

	if se.Status != EnhancementActive {
		return errors.New("enhancement is not active")
	}

	se.ScalingFactor = scalingFactor
	se.Timestamp = time.Now()
	return nil
}

// DeactivateEnhancement deactivates the scalability enhancement
func (se *ScalabilityEnhancement) DeactivateEnhancement() error {
	se.lock.Lock()
	defer se.lock.Unlock()

	if se.Status != EnhancementActive {
		return errors.New("enhancement is not active")
	}

	se.Status = EnhancementInactive
	se.Timestamp = time.Now()
	return nil
}

// ValidateEnhancement validates the enhancement details
func (se *ScalabilityEnhancement) ValidateEnhancement() error {
	se.lock.RLock()
	defer se.lock.RUnlock()

	if se.EnhancementID == "" || se.NodeID == "" {
		return errors.New("enhancement ID and node ID cannot be empty")
	}

	if se.ScalingFactor <= 0 {
		return errors.New("scaling factor must be greater than zero")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the enhancement
func (se *ScalabilityEnhancement) UpdateTimestamp() {
	se.lock.Lock()
	defer se.lock.Unlock()
	se.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the enhancement
func (se *ScalabilityEnhancement) GetTimestamp() time.Time {
	se.lock.RLock()
	defer se.lock.RUnlock()
	return se.Timestamp
}

// EncryptEnhancement encrypts the enhancement details
func (se *ScalabilityEnhancement) EncryptEnhancement(key []byte) (string, error) {
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

	data := fmt.Sprintf("%s|%s|%d|%s|%s",
		se.EnhancementID, se.NodeID, se.ScalingFactor, se.Status, se.Timestamp)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptEnhancement decrypts the enhancement details
func (se *ScalabilityEnhancement) DecryptEnhancement(encryptedData string, key []byte) error {
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

	se.EnhancementID = parts[0]
	se.NodeID = parts[1]
	se.ScalingFactor = utils.ParseInt64(parts[2])
	se.Status = parts[3]
	se.Timestamp = utils.ParseTime(parts[4])
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

func (se *ScalabilityEnhancement) String() string {
	return fmt.Sprintf("EnhancementID: %s, Status: %s, Timestamp: %s", se.EnhancementID, se.Status, se.Timestamp)
}
