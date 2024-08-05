package liquidity_pool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// SmartContract represents an interoperable smart contract
type SmartContract struct {
	ID         string
	Code       string
	Creator    string
	CreatedAt  time.Time
	Encrypted  bool
	Encryption string
}

// ContractManager manages multiple smart contracts
type ContractManager struct {
	Contracts map[string]*SmartContract
	Lock      sync.Mutex
}

// NewContractManager creates a new ContractManager instance
func NewContractManager() *ContractManager {
	return &ContractManager{
		Contracts: make(map[string]*SmartContract),
	}
}

// DeployContract deploys a new smart contract
func (manager *ContractManager) DeployContract(code, creator string, encrypted bool, encryption string) (*SmartContract, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	id, err := generateUniqueID(creator)
	if err != nil {
		return nil, err
	}

	contract := &SmartContract{
		ID:         id,
		Code:       code,
		Creator:    creator,
		CreatedAt:  time.Now(),
		Encrypted:  encrypted,
		Encryption: encryption,
	}

	if encrypted {
		encryptedCode, err := encryptContractCode(code, encryption)
		if err != nil {
			return nil, err
		}
		contract.Code = encryptedCode
	}

	manager.Contracts[id] = contract
	return contract, nil
}

// GetContract retrieves a smart contract by ID
func (manager *ContractManager) GetContract(id string) (*SmartContract, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	contract, exists := manager.Contracts[id]
	if !exists {
		return nil, errors.New("contract not found")
	}
	return contract, nil
}

// ExecuteContract executes a smart contract by ID
func (manager *ContractManager) ExecuteContract(id string, params map[string]interface{}) (string, error) {
	manager.Lock.Lock()
	defer manager.Lock.Unlock()

	contract, exists := manager.Contracts[id]
	if !exists {
		return "", errors.New("contract not found")
	}

	// Placeholder for actual execution logic
	result := fmt.Sprintf("Executed contract %s with params %v", id, params)
	return result, nil
}

// generateUniqueID generates a unique ID
func generateUniqueID(creator string) (string, error) {
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}

	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%s-%s", creator, hex.EncodeToString(randBytes))))
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// encryptContractCode encrypts the contract code using the specified encryption method
func encryptContractCode(code, method string) (string, error) {
	key := []byte("a very secret key") // This should be securely generated and stored
	switch method {
	case "aes":
		encryptedCode, err := encryptAES(code, key)
		if err != nil {
			return "", err
		}
		return encryptedCode, nil
	default:
		return "", errors.New("unsupported encryption method")
	}
}

// encryptAES encrypts text using AES
func encryptAES(text string, key []byte) (string, error) {
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

	ciphertext := gcm.Seal(nonce, nonce, []byte(text), nil)
	return hex.EncodeToString(ciphertext), nil
}

// generateSalt generates a random salt for hashing
func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	return salt, err
}

// hashPassword hashes a password using scrypt with a salt
func hashPassword(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, 32768, 8, 1, 32)
}
