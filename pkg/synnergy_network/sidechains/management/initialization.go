package management

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"sync"
)

// InitializationManager handles the initialization tasks in the blockchain
type InitializationManager struct {
	mutex          sync.Mutex
	nodeConfig     map[string]string
	encryptionKey  []byte
	initialization bool
}

// NewInitializationManager creates a new InitializationManager
func NewInitializationManager(encryptionKey string) *InitializationManager {
	return &InitializationManager{
		nodeConfig:     make(map[string]string),
		encryptionKey:  []byte(encryptionKey),
		initialization: false,
	}
}

// InitializeNode initializes a node with the provided configuration
func (im *InitializationManager) InitializeNode(config map[string]string) error {
	im.mutex.Lock()
	defer im.mutex.Unlock()

	if im.initialization {
		return errors.New("node already initialized")
	}

	for key, value := range config {
		im.nodeConfig[key] = value
	}
	im.initialization = true
	return nil
}

// IsInitialized checks if the node is already initialized
func (im *InitializationManager) IsInitialized() bool {
	im.mutex.Lock()
	defer im.mutex.Unlock()
	return im.initialization
}

// SetConfig sets a configuration value for a specific key
func (im *InitializationManager) SetConfig(key string, value string) {
	im.mutex.Lock()
	defer im.mutex.Unlock()
	im.nodeConfig[key] = value
}

// GetConfig retrieves a configuration value for a specific key
func (im *InitializationManager) GetConfig(key string) (string, error) {
	im.mutex.Lock()
	defer im.mutex.Unlock()
	value, exists := im.nodeConfig[key]
	if !exists {
		return "", errors.New("config key not found")
	}
	return value, nil
}

// EncryptConfig encrypts the node configuration using AES-GCM
func (im *InitializationManager) EncryptConfig() (string, error) {
	im.mutex.Lock()
	defer im.mutex.Unlock()
	data, err := serializeNodeConfig(im.nodeConfig)
	if err != nil {
		return "", err
	}
	encryptedData, err := im.encrypt(data)
	if err != nil {
		return "", err
	}
	return encryptedData, nil
}

// DecryptConfig decrypts the node configuration using AES-GCM
func (im *InitializationManager) DecryptConfig(encryptedData string) error {
	im.mutex.Lock()
	defer im.mutex.Unlock()
	data, err := im.decrypt(encryptedData)
	if err != nil {
		return err
	}
	nodeConfig, err := deserializeNodeConfig(data)
	if err != nil {
		return err
	}
	im.nodeConfig = nodeConfig
	return nil
}

// Helper function to encrypt data using AES-GCM
func (im *InitializationManager) encrypt(data []byte) (string, error) {
	block, err := aes.NewCipher(im.encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Helper function to decrypt data using AES-GCM
func (im *InitializationManager) decrypt(encryptedData string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(im.encryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// Helper function to serialize node configuration
func serializeNodeConfig(nodeConfig map[string]string) ([]byte, error) {
	return json.Marshal(nodeConfig)
}

// Helper function to deserialize node configuration
func deserializeNodeConfig(data []byte) (map[string]string, error) {
	var nodeConfig map[string]string
	err := json.Unmarshal(data, &nodeConfig)
	return nodeConfig, err
}
