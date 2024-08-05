package performance

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"github.com/synnergy_network/utils"
)

// ProtocolStackOptimization represents the protocol stack optimization settings
type ProtocolStackOptimization struct {
	OptimizationID string
	NodeID         string
	Layer          string
	Status         string
	Timestamp      time.Time
	lock           sync.RWMutex
}

const (
	OptimizationActive   = "ACTIVE"
	OptimizationInactive = "INACTIVE"
	OptimizationFailed   = "FAILED"
)

// NewProtocolStackOptimization initializes a new ProtocolStackOptimization instance
func NewProtocolStackOptimization(optimizationID, nodeID, layer string) *ProtocolStackOptimization {
	return &ProtocolStackOptimization{
		OptimizationID: optimizationID,
		NodeID:         nodeID,
		Layer:          layer,
		Status:         OptimizationActive,
		Timestamp:      time.Now(),
	}
}

// UpdateOptimization updates the protocol stack optimization
func (pso *ProtocolStackOptimization) UpdateOptimization(layer string) error {
	pso.lock.Lock()
	defer pso.lock.Unlock()

	if pso.Status != OptimizationActive {
		return errors.New("optimization is not active")
	}

	pso.Layer = layer
	pso.Timestamp = time.Now()
	return nil
}

// DeactivateOptimization deactivates the protocol stack optimization
func (pso *ProtocolStackOptimization) DeactivateOptimization() error {
	pso.lock.Lock()
	defer pso.lock.Unlock()

	if pso.Status != OptimizationActive {
		return errors.New("optimization is not active")
	}

	pso.Status = OptimizationInactive
	pso.Timestamp = time.Now()
	return nil
}

// ValidateOptimization validates the optimization details
func (pso *ProtocolStackOptimization) ValidateOptimization() error {
	pso.lock.RLock()
	defer pso.lock.RUnlock()

	if pso.OptimizationID == "" || pso.NodeID == "" || pso.Layer == "" {
		return errors.New("optimization ID, node ID, and layer cannot be empty")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the optimization
func (pso *ProtocolStackOptimization) UpdateTimestamp() {
	pso.lock.Lock()
	defer pso.lock.Unlock()
	pso.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the optimization
func (pso *ProtocolStackOptimization) GetTimestamp() time.Time {
	pso.lock.RLock()
	defer pso.lock.RUnlock()
	return pso.Timestamp
}

// EncryptOptimization encrypts the optimization details
func (pso *ProtocolStackOptimization) EncryptOptimization(key []byte) (string, error) {
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
		pso.OptimizationID, pso.NodeID, pso.Layer, pso.Status, pso.Timestamp)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptOptimization decrypts the optimization details
func (pso *ProtocolStackOptimization) DecryptOptimization(encryptedData string, key []byte) error {
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

	pso.OptimizationID = parts[0]
	pso.NodeID = parts[1]
	pso.Layer = parts[2]
	pso.Status = parts[3]
	pso.Timestamp = utils.ParseTime(parts[4])
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

func (pso *ProtocolStackOptimization) String() string {
	return fmt.Sprintf("OptimizationID: %s, Status: %s, Timestamp: %s", pso.OptimizationID, pso.Status, pso.Timestamp)
}
