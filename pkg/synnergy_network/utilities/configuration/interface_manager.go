package configuration

import (
	"errors"
	"fmt"
	"sync"

	"github.com/synthron_blockchain/pkg/layer0/utilities/encryption_utils"
	"github.com/synthron_blockchain/pkg/layer0/utilities/logging_utils"
)

// InterfaceManager handles dynamic interfaces and their configurations
type InterfaceManager struct {
	interfaces map[string]*InterfaceConfig
	mutex      sync.RWMutex
}

// InterfaceConfig represents the configuration for an interface
type InterfaceConfig struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Endpoint      string `json:"endpoint"`
	EncryptionKey string `json:"encryption_key"`
	Enabled       bool   `json:"enabled"`
}

// NewInterfaceManager creates a new InterfaceManager
func NewInterfaceManager() *InterfaceManager {
	return &InterfaceManager{
		interfaces: make(map[string]*InterfaceConfig),
	}
}

// AddInterface adds a new interface configuration
func (im *InterfaceManager) AddInterface(config *InterfaceConfig) error {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	if _, exists := im.interfaces[config.Name]; exists {
		return errors.New("interface already exists")
	}

	im.interfaces[config.Name] = config
	logging_utils.LogInfo(fmt.Sprintf("Interface %s added", config.Name))

	return nil
}

// UpdateInterface updates an existing interface configuration
func (im *InterfaceManager) UpdateInterface(config *InterfaceConfig) error {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	if _, exists := im.interfaces[config.Name]; !exists {
		return errors.New("interface does not exist")
	}

	im.interfaces[config.Name] = config
	logging_utils.LogInfo(fmt.Sprintf("Interface %s updated", config.Name))

	return nil
}

// RemoveInterface removes an interface configuration
func (im *InterfaceManager) RemoveInterface(name string) error {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	if _, exists := im.interfaces[name]; !exists {
		return errors.New("interface does not exist")
	}

	delete(im.interfaces, name)
	logging_utils.LogInfo(fmt.Sprintf("Interface %s removed", name))

	return nil
}

// GetInterface retrieves an interface configuration by name
func (im *InterfaceManager) GetInterface(name string) (*InterfaceConfig, error) {
	im.mutex.RLock()
	defer im.mutex.RUnlock()

	config, exists := im.interfaces[name]
	if !exists {
		return nil, errors.New("interface not found")
	}

	return config, nil
}

// ListInterfaces lists all available interface configurations
func (im *InterfaceManager) ListInterfaces() []*InterfaceConfig {
	im.mutex.RLock()
	defer im.mutex.RUnlock()

	var configs []*InterfaceConfig
	for _, config := range im.interfaces {
		configs = append(configs, config)
	}

	return configs
}

// EncryptInterfaceData encrypts data for a given interface
func (im *InterfaceManager) EncryptInterfaceData(interfaceName string, data []byte) ([]byte, error) {
	im.mutex.RLock()
	defer im.mutex.RUnlock()

	config, exists := im.interfaces[interfaceName]
	if !exists {
		return nil, errors.New("interface not found")
	}

	encryptedData, err := encryption_utils.Encrypt(data, config.EncryptionKey)
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}

// DecryptInterfaceData decrypts data for a given interface
func (im *InterfaceManager) DecryptInterfaceData(interfaceName string, encryptedData []byte) ([]byte, error) {
	im.mutex.RLock()
	defer im.mutex.RUnlock()

	config, exists := im.interfaces[interfaceName]
	if !exists {
		return nil, errors.New("interface not found")
	}

	data, err := encryption_utils.Decrypt(encryptedData, config.EncryptionKey)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// ValidateInterfaceConfig validates the interface configuration parameters
func ValidateInterfaceConfig(config *InterfaceConfig) error {
	if config.Name == "" {
		return errors.New("interface name is required")
	}
	if config.Type == "" {
		return errors.New("interface type is required")
	}
	if config.Endpoint == "" {
		return errors.New("interface endpoint is required")
	}
	if config.EncryptionKey == "" {
		return errors.New("encryption key is required")
	}
	return nil
}

// InitInterfaceManager initializes the InterfaceManager with initial configurations
func InitInterfaceManager(initialConfigs []*InterfaceConfig) (*InterfaceManager, error) {
	manager := NewInterfaceManager()

	for _, config := range initialConfigs {
		if err := ValidateInterfaceConfig(config); err != nil {
			return nil, err
		}

		if err := manager.AddInterface(config); err != nil {
			return nil, err
		}
	}

	return manager, nil
}
