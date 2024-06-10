package baas

import (
	"encoding/json"
	"errors"
	"log"

	"golang.org/x/crypto/scrypt"
)

// ServiceConfig defines the configuration structure for each blockchain service offered.
type ServiceConfig struct {
	ServiceName       string `json:"serviceName"`
	ServiceType       string `json:"serviceType"`
	MaxNodes          int    `json:"maxNodes"`
	EncryptionEnabled bool   `json:"encryptionEnabled"`
	AdminPublicKey    string `json:"adminPublicKey"`
}

// ConfigManager handles the operations for loading and saving service configurations.
type ConfigManager struct {
	Configurations []ServiceConfig
	StoragePath    string
}

// NewConfigManager initializes a new configuration manager with a default storage path.
func NewConfigManager(storagePath string) *ConfigManager {
	return &ConfigManager{
		StoragePath: storagePath,
	}
}

// LoadConfigurations loads the service configurations from a JSON file.
func (manager *ConfigManager) LoadConfigurations() error {
	data, err := os.ReadFile(manager.StoragePath)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &manager.Configurations)
	if err != nil {
		return err
	}

	log.Println("Configurations loaded successfully.")
	return nil
}

// SaveConfigurations saves the current configurations to a JSON file.
func (manager *ConfigManager) SaveConfigurations() error {
	data, err := json.Marshal(manager.Configurations)
	if err != nil {
		return err
	}

	err = os.WriteFile(manager.StoragePath, data, 0644)
	if err != nil {
		return err
	}

	log.Println("Configurations saved successfully.")
	return nil
}

// EncryptAdminKey encrypts the admin public key using AES-256 or Scrypt based on configuration.
func EncryptAdminKey(key string, useScrypt bool) ([]byte, error) {
	if useScrypt {
		salt := []byte{0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a}
		dk, err := scrypt.Key([]byte(key), salt, 16384, 8, 1, 32)
		if err != nil {
			return nil, err
		}
		return dk, nil
	}

	// Fallback to AES if Scrypt is not used
	return EncryptDataWithAES([]byte(key))
}

// EncryptDataWithAES encrypts data using AES-256 GCM.
func EncryptDataWithAES(data []byte) ([]byte, error) {
	// AES encryption logic to be implemented
	return data, errors.New("AES encryption not implemented")
}

func main() {
	configManager := NewConfigManager("/path/to/configurations.json")
	err := configManager.LoadConfigurations()
	if err != nil {
		log.Fatalf("Failed to load configurations: %v", err)
	}

	// Example: Encrypt the admin key using Scrypt
	encryptedKey, err := EncryptAdminKey("example-admin-key", true)
	if err != nil {
		log.Fatalf("Failed to encrypt admin key: %v", err)
	}
	log.Printf("Encrypted Admin Key: %x", encryptedKey)

	// Save configurations back to file
	err = configManager.SaveConfigurations()
	if err != nil {
		log.Fatalf("Failed to save configurations: %v", err)
	}
}
