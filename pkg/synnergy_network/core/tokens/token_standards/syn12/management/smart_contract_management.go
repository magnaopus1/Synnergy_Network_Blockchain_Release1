package management

import (
	"errors"
	"time"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
)

// SmartContract represents the structure of a smart contract within the SYN12 token framework.
type SmartContract struct {
	ID            string
	CreationDate  time.Time
	Status        string
	Script        string
	EncryptionKey []byte
}

// SmartContractManager manages the lifecycle of smart contracts.
type SmartContractManager struct {
	contracts map[string]SmartContract
	key       []byte
}

// NewSmartContractManager creates a new instance of SmartContractManager.
func NewSmartContractManager(masterKey string) *SmartContractManager {
	hashedKey := sha256.Sum256([]byte(masterKey))
	return &SmartContractManager{
		contracts: make(map[string]SmartContract),
		key:       hashedKey[:],
	}
}

// CreateSmartContract creates a new smart contract with the given script.
func (manager *SmartContractManager) CreateSmartContract(script string) (SmartContract, error) {
	contractID := generateContractID()
	encryptedScript, err := manager.EncryptScript(script)
	if err != nil {
		return SmartContract{}, err
	}

	contract := SmartContract{
		ID:           contractID,
		CreationDate: time.Now(),
		Status:       "Active",
		Script:       encryptedScript,
		EncryptionKey: manager.key,
	}
	manager.contracts[contract.ID] = contract
	return contract, nil
}

// UpdateSmartContract updates an existing smart contract by ID.
func (manager *SmartContractManager) UpdateSmartContract(contractID, newScript string) (SmartContract, error) {
	contract, exists := manager.contracts[contractID]
	if !exists {
		return SmartContract{}, errors.New("smart contract not found")
	}

	encryptedScript, err := manager.EncryptScript(newScript)
	if err != nil {
		return SmartContract{}, err
	}

	contract.Script = encryptedScript
	manager.contracts[contract.ID] = contract
	return contract, nil
}

// GetSmartContract retrieves a smart contract by ID.
func (manager *SmartContractManager) GetSmartContract(contractID string) (SmartContract, error) {
	contract, exists := manager.contracts[contractID]
	if !exists {
		return SmartContract{}, errors.New("smart contract not found")
	}
	return contract, nil
}

// EncryptScript encrypts the smart contract script.
func (manager *SmartContractManager) EncryptScript(script string) (string, error) {
	block, err := aes.NewCipher(manager.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(script), nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptScript decrypts the smart contract script.
func (manager *SmartContractManager) DecryptScript(encryptedScript string) (string, error) {
	data, err := hex.DecodeString(encryptedScript)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(manager.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// generateContractID generates a unique identifier for a smart contract.
func generateContractID() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 12)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}
