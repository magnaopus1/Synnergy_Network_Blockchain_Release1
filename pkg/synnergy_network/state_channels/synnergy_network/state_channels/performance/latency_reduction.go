package performance

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"github.com/synnergy_network/utils"
)

// LatencyReduction represents the latency reduction settings
type LatencyReduction struct {
	NodeID       string
	Latency      int64
	TargetLatency int64
	Status       string
	Timestamp    time.Time
	lock         sync.RWMutex
}

const (
	LatencyReductionActive   = "ACTIVE"
	LatencyReductionInactive = "INACTIVE"
	LatencyReductionFailed   = "FAILED"
)

// NewLatencyReduction initializes a new LatencyReduction instance
func NewLatencyReduction(nodeID string, latency, targetLatency int64) *LatencyReduction {
	return &LatencyReduction{
		NodeID:       nodeID,
		Latency:      latency,
		TargetLatency: targetLatency,
		Status:       LatencyReductionActive,
		Timestamp:    time.Now(),
	}
}

// UpdateLatencyMetrics updates the latency metrics
func (lr *LatencyReduction) UpdateLatencyMetrics(latency, targetLatency int64) error {
	lr.lock.Lock()
	defer lr.lock.Unlock()

	if lr.Status != LatencyReductionActive {
		return errors.New("latency reduction is not active")
	}

	lr.Latency = latency
	lr.TargetLatency = targetLatency
	lr.Timestamp = time.Now()
	return nil
}

// DeactivateLatencyReduction deactivates the latency reduction
func (lr *LatencyReduction) DeactivateLatencyReduction() error {
	lr.lock.Lock()
	defer lr.lock.Unlock()

	if lr.Status != LatencyReductionActive {
		return errors.New("latency reduction is not active")
	}

	lr.Status = LatencyReductionInactive
	lr.Timestamp = time.Now()
	return nil
}

// ValidateLatencyMetrics validates the latency metrics
func (lr *LatencyReduction) ValidateLatencyMetrics() error {
	lr.lock.RLock()
	defer lr.lock.RUnlock()

	if lr.Latency < 0 {
		return errors.New("latency cannot be negative")
	}

	if lr.TargetLatency <= 0 {
		return errors.New("target latency must be greater than zero")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the latency reduction
func (lr *LatencyReduction) UpdateTimestamp() {
	lr.lock.Lock()
	defer lr.lock.Unlock()
	lr.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the latency reduction
func (lr *LatencyReduction) GetTimestamp() time.Time {
	lr.lock.RLock()
	defer lr.lock.RUnlock()
	return lr.Timestamp
}

// EncryptLatencyReduction encrypts the latency reduction details
func (lr *LatencyReduction) EncryptLatencyReduction(key []byte) (string, error) {
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

	data := fmt.Sprintf("%s|%d|%d|%s",
		lr.NodeID, lr.Latency, lr.TargetLatency, lr.Status)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptLatencyReduction decrypts the latency reduction details
func (lr *LatencyReduction) DecryptLatencyReduction(encryptedData string, key []byte) error {
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
	if len(parts) != 4 {
		return errors.New("invalid encrypted data format")
	}

	lr.NodeID = parts[0]
	lr.Latency = utils.ParseInt64(parts[1])
	lr.TargetLatency = utils.ParseInt64(parts[2])
	lr.Status = parts[3]
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

func (lr *LatencyReduction) String() string {
	return fmt.Sprintf("NodeID: %s, Status: %s, Timestamp: %s", lr.NodeID, lr.Status, lr.Timestamp)
}
