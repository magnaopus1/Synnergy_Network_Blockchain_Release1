package quantum_interoperability

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)



// NewKeyManager creates a new KeyManager
func NewKeyManager() *KeyManager {
	return &KeyManager{
		quantumKeys:   make(map[string][]byte),
		classicalKeys: make(map[string][]byte),
	}
}

// AddQuantumKey adds a quantum-resistant key to the manager
func (km *KeyManager) AddQuantumKey(chainID string, password []byte, useArgon2 bool) error {
	salt, err := generateRandomData(SaltLen)
	if err != nil {
		return err
	}

	var key []byte
	if useArgon2 {
		key = GenerateArgon2Key(password, salt)
	} else {
		key, err = GenerateScryptKey(password, salt)
		if err != nil {
			return err
		}
	}
	km.quantumKeys[chainID] = key
	return nil
}

// GetQuantumKey retrieves a quantum-resistant key from the manager
func (km *KeyManager) GetQuantumKey(chainID string) ([]byte, error) {
	key, exists := km.quantumKeys[chainID]
	if !exists {
		return nil, fmt.Errorf("quantum key not found for chain ID: %s", chainID)
	}
	return key, nil
}

// AddClassicalKey adds a classical key to the manager
func (km *KeyManager) AddClassicalKey(chainID string, password []byte, useArgon2 bool) error {
	salt, err := generateRandomData(SaltLen)
	if err != nil {
		return err
	}

	var key []byte
	if useArgon2 {
		key = GenerateArgon2Key(password, salt)
	} else {
		key, err = GenerateScryptKey(password, salt)
		if err != nil {
			return err
		}
	}
	km.classicalKeys[chainID] = key
	return nil
}

// GetClassicalKey retrieves a classical key from the manager
func (km *KeyManager) GetClassicalKey(chainID string) ([]byte, error) {
	key, exists := km.classicalKeys[chainID]
	if !exists {
		return nil, fmt.Errorf("classical key not found for chain ID: %s", chainID)
	}
	return key, nil
}

// GenerateArgon2Key generates a key using Argon2
func GenerateArgon2Key(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, Argon2KeyLen)
}

// GenerateScryptKey generates a key using Scrypt
func GenerateScryptKey(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, ScryptN, ScryptR, ScryptP, ScryptKeyLen)
}



// NewSecureCrossChainTransaction creates a new secure cross-chain transaction
func NewSecureCrossChainTransaction(source, destination string, data []byte) (*SecureCrossChainTransaction, error) {
	txID, err := generateTransactionID()
	if err != nil {
		return nil, err
	}
	signature := generateSignature(data)
	return &SecureCrossChainTransaction{
		ID:          txID,
		Source:      source,
		Destination: destination,
		Data:        data,
		Signature:   signature,
		Timestamp:   time.Now(),
	}, nil
}

// ValidateSignature validates the transaction signature
func (tx *SecureCrossChainTransaction) ValidateSignature() bool {
	expectedSignature := generateSignature(tx.Data)
	return subtle.ConstantTimeCompare(tx.Signature, expectedSignature) == 1
}

// PrintDetails prints the transaction details
func (tx *SecureCrossChainTransaction) PrintDetails() {
	fmt.Printf("Transaction ID: %s\nSource: %s\nDestination: %s\nTimestamp: %s\n",
		tx.ID, tx.Source, tx.Destination, tx.Timestamp)
	fmt.Printf("Data: %x\nSignature: %x\n", tx.Data, tx.Signature)
}

// NewCrossChainValidator creates a new CrossChainValidator
func NewCrossChainValidator(km *KeyManager) *CrossChainValidator {
	return &CrossChainValidator{keyManager: km}
}

// ValidateTransaction validates a cross-chain transaction
func (v *CrossChainValidator) ValidateTransaction(chainID string, data []byte) (bool, error) {
	key, err := v.keyManager.GetQuantumKey(chainID)
	if err != nil {
		return false, err
	}
	expectedSignature := generateSignatureWithKey(data, key)
	return subtle.ConstantTimeCompare(expectedSignature, generateSignature(data)) == 1, nil
}

// Helper function to generate random data
func generateRandomData(size int) ([]byte, error) {
	data := make([]byte, size)
	_, err := rand.Read(data)
	return data, err
}

// Helper function to generate transaction ID
func generateTransactionID() (string, error) {
	data, err := generateRandomData(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

// Helper function to generate signature
func generateSignature(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// Helper function to generate signature with a key
func generateSignatureWithKey(data, key []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	hash.Write(key)
	return hash.Sum(nil)
}


// NewKeyManager creates a new KeyManager
func NewKeyManager() *KeyManager {
	return &KeyManager{
		quantumKeys:   make(map[string][]byte),
		classicalKeys: make(map[string][]byte),
	}
}

// AddQuantumKey adds a quantum-resistant key to the manager
func (km *KeyManager) AddQuantumKey(chainID string, password []byte, useArgon2 bool) error {
	salt, err := generateRandomData(SaltLen)
	if err != nil {
		return err
	}

	var key []byte
	if useArgon2 {
		key = GenerateArgon2Key(password, salt)
	} else {
		key, err = GenerateScryptKey(password, salt)
		if err != nil {
			return err
		}
	}
	km.quantumKeys[chainID] = key
	return nil
}

// GetQuantumKey retrieves a quantum-resistant key from the manager
func (km *KeyManager) GetQuantumKey(chainID string) ([]byte, error) {
	key, exists := km.quantumKeys[chainID]
	if !exists {
		return nil, fmt.Errorf("quantum key not found for chain ID: %s", chainID)
	}
	return key, nil
}

// AddClassicalKey adds a classical key to the manager
func (km *KeyManager) AddClassicalKey(chainID string, password []byte, useArgon2 bool) error {
	salt, err := generateRandomData(SaltLen)
	if err != nil {
		return err
	}

	var key []byte
	if useArgon2 {
		key = GenerateArgon2Key(password, salt)
	} else {
		key, err = GenerateScryptKey(password, salt)
		if err != nil {
			return err
		}
	}
	km.classicalKeys[chainID] = key
	return nil
}

// GetClassicalKey retrieves a classical key from the manager
func (km *KeyManager) GetClassicalKey(chainID string) ([]byte, error) {
	key, exists := km.classicalKeys[chainID]
	if !exists {
		return nil, fmt.Errorf("classical key not found for chain ID: %s", chainID)
	}
	return key, nil
}

// GenerateArgon2Key generates a key using Argon2
func GenerateArgon2Key(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, Argon2KeyLen)
}

// GenerateScryptKey generates a key using Scrypt
func GenerateScryptKey(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, ScryptN, ScryptR, ScryptP, ScryptKeyLen)
}

// NewSecureCrossChainTransaction creates a new secure cross-chain transaction
func NewSecureCrossChainTransaction(source, destination string, data []byte) (*SecureCrossChainTransaction, error) {
	txID, err := generateTransactionID()
	if err != nil {
		return nil, err
	}
	signature := generateSignature(data)
	return &SecureCrossChainTransaction{
		ID:          txID,
		Source:      source,
		Destination: destination,
		Data:        data,
		Signature:   signature,
		Timestamp:   time.Now(),
	}, nil
}

// ValidateSignature validates the transaction signature
func (tx *SecureCrossChainTransaction) ValidateSignature() bool {
	expectedSignature := generateSignature(tx.Data)
	return subtle.ConstantTimeCompare(tx.Signature, expectedSignature) == 1
}

// PrintDetails prints the transaction details
func (tx *SecureCrossChainTransaction) PrintDetails() {
	fmt.Printf("Transaction ID: %s\nSource: %s\nDestination: %s\nTimestamp: %s\n",
		tx.ID, tx.Source, tx.Destination, tx.Timestamp)
	fmt.Printf("Data: %x\nSignature: %x\n", tx.Data, tx.Signature)
}

// CrossChainValidator struct to validate cross-chain transactions
type CrossChainValidator struct {
	keyManager *KeyManager
}

// NewCrossChainValidator creates a new CrossChainValidator
func NewCrossChainValidator(km *KeyManager) *CrossChainValidator {
	return &CrossChainValidator{keyManager: km}
}

// ValidateTransaction validates a cross-chain transaction
func (v *CrossChainValidator) ValidateTransaction(chainID string, data []byte) (bool, error) {
	key, err := v.keyManager.GetQuantumKey(chainID)
	if err != nil {
		return false, err
	}
	expectedSignature := generateSignatureWithKey(data, key)
	return subtle.ConstantTimeCompare(expectedSignature, generateSignature(data)) == 1, nil
}

// Helper function to generate random data
func generateRandomData(size int) ([]byte, error) {
	data := make([]byte, size)
	_, err := rand.Read(data)
	return data, err
}

// Helper function to generate transaction ID
func generateTransactionID() (string, error) {
	data, err := generateRandomData(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

// Helper function to generate signature
func generateSignature(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// Helper function to generate signature with a key
func generateSignatureWithKey(data, key []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	hash.Write(key)
	return hash.Sum(nil)
}
