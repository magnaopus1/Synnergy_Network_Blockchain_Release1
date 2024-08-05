package privacy

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"github.com/synnergy_network/utils"
)

// ScalablePrivacy represents scalable privacy settings
type ScalablePrivacy struct {
	PrivacyID     string
	NodeID        string
	PrivacyLevel  int
	Status        string
	Timestamp     time.Time
	lock          sync.RWMutex
}

const (
	PrivacyActive   = "ACTIVE"
	PrivacyInactive = "INACTIVE"
	PrivacyFailed   = "FAILED"
)

// NewScalablePrivacy initializes a new ScalablePrivacy instance
func NewScalablePrivacy(privacyID, nodeID string, privacyLevel int) *ScalablePrivacy {
	return &ScalablePrivacy{
		PrivacyID:    privacyID,
		NodeID:       nodeID,
		PrivacyLevel: privacyLevel,
		Status:       PrivacyActive,
		Timestamp:    time.Now(),
	}
}

// UpdatePrivacy updates the scalable privacy settings
func (sp *ScalablePrivacy) UpdatePrivacy(privacyLevel int) error {
	sp.lock.Lock()
	defer sp.lock.Unlock()

	if sp.Status != PrivacyActive {
		return errors.New("privacy is not active")
	}

	sp.PrivacyLevel = privacyLevel
	sp.Timestamp = time.Now()
	return nil
}

// DeactivatePrivacy deactivates the scalable privacy
func (sp *ScalablePrivacy) DeactivatePrivacy() error {
	sp.lock.Lock()
	defer sp.lock.Unlock()

	if sp.Status != PrivacyActive {
		return errors.New("privacy is not active")
	}

	sp.Status = PrivacyInactive
	sp.Timestamp = time.Now()
	return nil
}

// ValidatePrivacy validates the privacy details
func (sp *ScalablePrivacy) ValidatePrivacy() error {
	sp.lock.RLock()
	defer sp.lock.RUnlock()

	if sp.PrivacyID == "" || sp.NodeID == "" {
		return errors.New("privacy ID and node ID cannot be empty")
	}

	if sp.PrivacyLevel <= 0 {
		return errors.New("privacy level must be greater than zero")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the privacy settings
func (sp *ScalablePrivacy) UpdateTimestamp() {
	sp.lock.Lock()
	defer sp.lock.Unlock()
	sp.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the privacy settings
func (sp *ScalablePrivacy) GetTimestamp() time.Time {
	sp.lock.RLock()
	defer sp.lock.RUnlock()
	return sp.Timestamp
}

// EncryptPrivacy encrypts the privacy settings
func (sp *ScalablePrivacy) EncryptPrivacy(key []byte) (string, error) {
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
		sp.PrivacyID, sp.NodeID, sp.PrivacyLevel, sp.Status, sp.Timestamp)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptPrivacy decrypts the privacy settings
func (sp *ScalablePrivacy) DecryptPrivacy(encryptedData string, key []byte) error {
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

	sp.PrivacyID = parts[0]
	sp.NodeID = parts[1]
	sp.PrivacyLevel = utils.ParseInt(parts[2])
	sp.Status = parts[3]
	sp.Timestamp = utils.ParseTime(parts[4])
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

func (sp *ScalablePrivacy) String() string {
	return fmt.Sprintf("PrivacyID: %s, PrivacyLevel: %d, Status: %s, Timestamp: %s",
		sp.PrivacyID, sp.PrivacyLevel, sp.Status, sp.Timestamp)
}
