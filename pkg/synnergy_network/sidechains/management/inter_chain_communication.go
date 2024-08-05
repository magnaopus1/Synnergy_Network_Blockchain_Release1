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

// InterChainCommunicationManager handles inter-chain communication tasks in the blockchain
type InterChainCommunicationManager struct {
	mutex         sync.Mutex
	chainConfig   map[string]map[string]string
	encryptionKey []byte
}

// NewInterChainCommunicationManager creates a new InterChainCommunicationManager
func NewInterChainCommunicationManager(encryptionKey string) *InterChainCommunicationManager {
	return &InterChainCommunicationManager{
		chainConfig:   make(map[string]map[string]string),
		encryptionKey: []byte(encryptionKey),
	}
}

// RegisterChain registers a new chain with its configuration
func (iccm *InterChainCommunicationManager) RegisterChain(chainID string, config map[string]string) error {
	iccm.mutex.Lock()
	defer iccm.mutex.Unlock()

	if _, exists := iccm.chainConfig[chainID]; exists {
		return errors.New("chain already registered")
	}

	iccm.chainConfig[chainID] = config
	return nil
}

// UpdateChainConfig updates the configuration of an existing chain
func (iccm *InterChainCommunicationManager) UpdateChainConfig(chainID string, config map[string]string) error {
	iccm.mutex.Lock()
	defer iccm.mutex.Unlock()

	if _, exists := iccm.chainConfig[chainID]; !exists {
		return errors.New("chain not registered")
	}

	iccm.chainConfig[chainID] = config
	return nil
}

// GetChainConfig retrieves the configuration of a specific chain
func (iccm *InterChainCommunicationManager) GetChainConfig(chainID string) (map[string]string, error) {
	iccm.mutex.Lock()
	defer iccm.mutex.Unlock()

	config, exists := iccm.chainConfig[chainID]
	if !exists {
		return nil, errors.New("chain not registered")
	}
	return config, nil
}

// EncryptChainConfig encrypts the chain configuration using AES-GCM
func (iccm *InterChainCommunicationManager) EncryptChainConfig(chainID string) (string, error) {
	iccm.mutex.Lock()
	defer iccm.mutex.Unlock()

	config, exists := iccm.chainConfig[chainID]
	if !exists {
		return "", errors.New("chain not registered")
	}

	data, err := serializeChainConfig(config)
	if err != nil {
		return "", err
	}
	encryptedData, err := iccm.encrypt(data)
	if err != nil {
		return "", err
	}
	return encryptedData, nil
}

// DecryptChainConfig decrypts the chain configuration using AES-GCM
func (iccm *InterChainCommunicationManager) DecryptChainConfig(chainID string, encryptedData string) error {
	iccm.mutex.Lock()
	defer iccm.mutex.Unlock()

	data, err := iccm.decrypt(encryptedData)
	if err != nil {
		return err
	}
	chainConfig, err := deserializeChainConfig(data)
	if err != nil {
		return err
	}
	iccm.chainConfig[chainID] = chainConfig
	return nil
}

// Helper function to encrypt data using AES-GCM
func (iccm *InterChainCommunicationManager) encrypt(data []byte) (string, error) {
	block, err := aes.NewCipher(iccm.encryptionKey)
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
func (iccm *InterChainCommunicationManager) decrypt(encryptedData string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(iccm.encryptionKey)
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

// Helper function to serialize chain configuration
func serializeChainConfig(chainConfig map[string]string) ([]byte, error) {
	return json.Marshal(chainConfig)
}

// Helper function to deserialize chain configuration
func deserializeChainConfig(data []byte) (map[string]string, error) {
	var chainConfig map[string]string
	err := json.Unmarshal(data, &chainConfig)
	return chainConfig, err
}

// LogEvent logs important events related to inter-chain communication
func (iccm *InterChainCommunicationManager) LogEvent(event string) {
	log.Println(event)
}
