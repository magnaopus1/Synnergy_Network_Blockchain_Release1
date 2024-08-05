package performance

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"github.com/synnergy_network/utils"
)

// AdvancedNetworkInfrastructure represents the advanced network infrastructure settings
type AdvancedNetworkInfrastructure struct {
	NodeID        string
	Latency       int64
	Bandwidth     int64
	PacketLoss    float64
	Status        string
	Timestamp     time.Time
	lock          sync.RWMutex
}

const (
	InfrastructureActive   = "ACTIVE"
	InfrastructureInactive = "INACTIVE"
	InfrastructureFailed   = "FAILED"
)

// NewAdvancedNetworkInfrastructure initializes a new AdvancedNetworkInfrastructure instance
func NewAdvancedNetworkInfrastructure(nodeID string, latency, bandwidth int64, packetLoss float64) *AdvancedNetworkInfrastructure {
	return &AdvancedNetworkInfrastructure{
		NodeID:     nodeID,
		Latency:    latency,
		Bandwidth:  bandwidth,
		PacketLoss: packetLoss,
		Status:     InfrastructureActive,
		Timestamp:  time.Now(),
	}
}

// UpdateNetworkMetrics updates the network metrics
func (ani *AdvancedNetworkInfrastructure) UpdateNetworkMetrics(latency, bandwidth int64, packetLoss float64) error {
	ani.lock.Lock()
	defer ani.lock.Unlock()

	if ani.Status != InfrastructureActive {
		return errors.New("infrastructure is not active")
	}

	ani.Latency = latency
	ani.Bandwidth = bandwidth
	ani.PacketLoss = packetLoss
	ani.Timestamp = time.Now()
	return nil
}

// DeactivateInfrastructure deactivates the infrastructure
func (ani *AdvancedNetworkInfrastructure) DeactivateInfrastructure() error {
	ani.lock.Lock()
	defer ani.lock.Unlock()

	if ani.Status != InfrastructureActive {
		return errors.New("infrastructure is not active")
	}

	ani.Status = InfrastructureInactive
	ani.Timestamp = time.Now()
	return nil
}

// ValidateNetworkMetrics validates the network metrics
func (ani *AdvancedNetworkInfrastructure) ValidateNetworkMetrics() error {
	ani.lock.RLock()
	defer ani.lock.RUnlock()

	if ani.Latency < 0 {
		return errors.New("latency cannot be negative")
	}

	if ani.Bandwidth <= 0 {
		return errors.New("bandwidth must be greater than zero")
	}

	if ani.PacketLoss < 0 || ani.PacketLoss > 100 {
		return errors.New("packet loss must be between 0 and 100")
	}

	return nil
}

// UpdateTimestamp updates the timestamp of the network infrastructure
func (ani *AdvancedNetworkInfrastructure) UpdateTimestamp() {
	ani.lock.Lock()
	defer ani.lock.Unlock()
	ani.Timestamp = time.Now()
}

// GetTimestamp returns the timestamp of the network infrastructure
func (ani *AdvancedNetworkInfrastructure) GetTimestamp() time.Time {
	ani.lock.RLock()
	defer ani.lock.RUnlock()
	return ani.Timestamp
}

// EncryptInfrastructure encrypts the network infrastructure details
func (ani *AdvancedNetworkInfrastructure) EncryptInfrastructure(key []byte) (string, error) {
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

	data := fmt.Sprintf("%s|%d|%d|%f|%s",
		ani.NodeID, ani.Latency, ani.Bandwidth, ani.PacketLoss, ani.Status)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptInfrastructure decrypts the network infrastructure details
func (ani *AdvancedNetworkInfrastructure) DecryptInfrastructure(encryptedData string, key []byte) error {
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

	ani.NodeID = parts[0]
	ani.Latency = utils.ParseInt64(parts[1])
	ani.Bandwidth = utils.ParseInt64(parts[2])
	ani.PacketLoss = utils.ParseFloat64(parts[3])
	ani.Status = parts[4]
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

func (ani *AdvancedNetworkInfrastructure) String() string {
	return fmt.Sprintf("NodeID: %s, Status: %s, Timestamp: %s", ani.NodeID, ani.Status, ani.Timestamp)
}
