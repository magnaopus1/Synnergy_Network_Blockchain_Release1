package baas

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"log"
	"os"
)

// BlockchainService represents a generic blockchain service instance.
type BlockchainService struct {
	ID          string `json:"id"`
	ServiceType string `json:"service_type"`
	Status      string `json:"status"`
	Config      ServiceConfig `json:"config"`
}

// ServiceConfig stores configuration for various blockchain services.
type ServiceConfig struct {
	NodeCount int    `json:"node_count"`
	Network   string `json:"network"`
}

// BaaSPlatform manages the lifecycle of blockchain services.
type BaaSPlatform struct {
	Services map[string]*BlockchainService
}

// NewBaaSPlatform initializes a new Blockchain-as-a-Service platform.
func NewBaaSPlatform() *BaaSPlatform {
	return &BaaSPlatform{
		Services: make(map[string]*BlockchainService),
	}
}

// CreateService provisions a new blockchain service based on the provided configuration.
func (bp *BaaSPlatform) CreateService(config ServiceConfig) (*BlockchainService, error) {
	serviceID := generateServiceID()
	service := &BlockchainService{
		ID:          serviceID,
		ServiceType: "blockchain",
		Status:      "active",
		Config:      config,
	}
	bp.Services[serviceID] = service
	log.Printf("Service %s created successfully\n", serviceID)
	return service, nil
}

// StopService deactivates a blockchain service.
func (bp *BaaSPlatform) StopService(serviceID string) error {
	if service, exists := bp.Services[serviceID]; exists {
		service.Status = "inactive"
		log.Printf("Service %s stopped successfully\n", serviceID)
		return nil
	}
	return errors.New("service not found")
}

// EncryptServiceConfig encrypts the service configuration to ensure its confidentiality.
func EncryptServiceConfig(config ServiceConfig) ([]byte, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	key := []byte("your-32-byte-long-key-here") // Ensure key is 32 bytes for AES-256
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := os.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	encryptedData := gcm.Seal(nonce, nonce, data, nil)
	return encryptedData, nil
}

// generateServiceID generates a unique identifier for a service.
func generateServiceID() string {
	// Implementation for generating a unique service ID
	return "service-" + generateRandomString(10)
}

// generateRandomString generates a random string of a given length.
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func main() {
	platform := NewBaaSPlatform()
	_, err := platform.CreateService(ServiceConfig{
		NodeCount: 5,
		Network:   "mainnet",
	})
	if err != nil {
		log.Fatal(err)
	}
}
