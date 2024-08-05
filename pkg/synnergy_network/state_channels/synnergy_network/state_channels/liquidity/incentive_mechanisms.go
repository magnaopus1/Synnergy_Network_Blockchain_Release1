package liquidity

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

// IncentiveMechanism represents an incentive mechanism for liquidity management
type IncentiveMechanism struct {
	IncentiveID     string
	PoolID          string
	ParticipantID   string
	IncentiveAmount int64
	Timestamp       time.Time
	Status          string
	lock            sync.RWMutex
}

const (
	IncentiveActive   = "ACTIVE"
	IncentiveInactive = "INACTIVE"
	IncentiveClaimed  = "CLAIMED"
)

// NewIncentiveMechanism initializes a new IncentiveMechanism instance
func NewIncentiveMechanism(incentiveID, poolID, participantID string, incentiveAmount int64) *IncentiveMechanism {
	return &IncentiveMechanism{
		IncentiveID:     incentiveID,
		PoolID:          poolID,
		ParticipantID:   participantID,
		IncentiveAmount: incentiveAmount,
		Timestamp:       time.Now(),
		Status:          IncentiveActive,
	}
}

// ClaimIncentive claims the incentive
func (im *IncentiveMechanism) ClaimIncentive() error {
	im.lock.Lock()
	defer im.lock.Unlock()

	if im.Status != IncentiveActive {
		return errors.New("incentive is not active")
	}

	im.Status = IncentiveClaimed
	im.Timestamp = time.Now()
	return nil
}

// DeactivateIncentive deactivates the incentive
func (im *IncentiveMechanism) DeactivateIncentive() error {
	im.lock.Lock()
	defer im.lock.Unlock()

	if im.Status != IncentiveActive {
		return errors.New("incentive is not active")
	}

	im.Status = IncentiveInactive
	im.Timestamp = time.Now()
	return nil
}

// EncryptIncentive encrypts the incentive details
func (im *IncentiveMechanism) EncryptIncentive(key []byte) (string, error) {
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

	data := fmt.Sprintf("%s|%s|%s|%d|%s",
		im.IncentiveID, im.PoolID, im.ParticipantID, im.IncentiveAmount, im.Status)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptIncentive decrypts the incentive details
func (im *IncentiveMechanism) DecryptIncentive(encryptedData string, key []byte) error {
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

	im.IncentiveID = parts[0]
	im.PoolID = parts[1]
	im.ParticipantID = parts[2]
	im.IncentiveAmount = utils.ParseInt64(parts[3])
	im.Status = parts[4]
	return nil
}

// GetIncentiveDetails returns the details of the incentive
func (im *IncentiveMechanism) GetIncentiveDetails() (string, string, string, int64, string) {
	im.lock.RLock()
	defer im.lock.RUnlock()
	return im.IncentiveID, im.PoolID, im.ParticipantID, im.IncentiveAmount, im.Status
}

// ValidateIncentive validates the incentive details
func (im *IncentiveMechanism) ValidateIncentive() error {
	im.lock.RLock()
	defer im.lock.RUnlock()

	if im.IncentiveID == "" || im.PoolID == "" || im.ParticipantID == "" {
		return errors.New("incentive, pool, and participant IDs cannot be empty")
	}

	if im.IncentiveAmount <= 0 {
		return errors.New("incentive amount must be greater than zero")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the incentive
func (im *IncentiveMechanism) UpdateTimestamp() {
	im.lock.Lock()
	defer im.lock.Unlock()
	im.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the incentive
func (im *IncentiveMechanism) GetTimestamp() time.Time {
	im.lock.RLock()
	defer im.lock.RUnlock()
	return im.Timestamp
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

func (im *IncentiveMechanism) String() string {
	return fmt.Sprintf("IncentiveID: %s, PoolID: %s, ParticipantID: %s, Status: %s, Timestamp: %s", im.IncentiveID, im.PoolID, im.ParticipantID, im.Status, im.Timestamp)
}
