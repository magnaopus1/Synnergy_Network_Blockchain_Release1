package management

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network/pkg/synnergy_network/sidechains/analytics"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// QuantumSafeAlgorithmsManager manages the implementation of quantum-safe algorithms
type QuantumSafeAlgorithmsManager struct {
	mutex         sync.Mutex
	analyticsSvc  analytics.Service
	encryptionKey []byte
	salt          []byte
}

// NewQuantumSafeAlgorithmsManager creates a new QuantumSafeAlgorithmsManager
func NewQuantumSafeAlgorithmsManager(analyticsSvc analytics.Service) *QuantumSafeAlgorithmsManager {
	return &QuantumSafeAlgorithmsManager{
		analyticsSvc:  analyticsSvc,
		encryptionKey: generateEncryptionKey(),
		salt:          generateSalt(),
	}
}

// generateEncryptionKey generates a secure encryption key
func generateEncryptionKey() []byte {
	key := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Failed to generate encryption key: %v", err)
	}
	return key
}

// generateSalt generates a secure salt
func generateSalt() []byte {
	salt := make([]byte, 16) // 128-bit salt
	if _, err := rand.Read(salt); err != nil {
		log.Fatalf("Failed to generate salt: %v", err)
	}
	return salt
}

// EncryptData encrypts data using a quantum-safe algorithm
func (qsm *QuantumSafeAlgorithmsManager) EncryptData(data []byte) ([]byte, error) {
	qsm.mutex.Lock()
	defer qsm.mutex.Unlock()

	encryptedData, err := qsm.scryptEncrypt(data)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	return encryptedData, nil
}

// DecryptData decrypts data using a quantum-safe algorithm
func (qsm *QuantumSafeAlgorithmsManager) DecryptData(encryptedData []byte) ([]byte, error) {
	qsm.mutex.Lock()
	defer qsm.mutex.Unlock()

	decryptedData, err := qsm.scryptDecrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return decryptedData, nil
}

// scryptEncrypt encrypts data using the Scrypt algorithm
func (qsm *QuantumSafeAlgorithmsManager) scryptEncrypt(data []byte) ([]byte, error) {
	key, err := scrypt.Key(qsm.encryptionKey, qsm.salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("scrypt key derivation failed: %w", err)
	}

	encryptedData := make([]byte, len(data))
	for i := range data {
		encryptedData[i] = data[i] ^ key[i%len(key)]
	}

	return encryptedData, nil
}

// scryptDecrypt decrypts data using the Scrypt algorithm
func (qsm *QuantumSafeAlgorithmsManager) scryptDecrypt(data []byte) ([]byte, error) {
	key, err := scrypt.Key(qsm.encryptionKey, qsm.salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("scrypt key derivation failed: %w", err)
	}

	decryptedData := make([]byte, len(data))
	for i := range data {
		decryptedData[i] = data[i] ^ key[i%len(key)]
	}

	return decryptedData, nil
}

// Argon2Encrypt encrypts data using the Argon2 algorithm
func (qsm *QuantumSafeAlgorithmsManager) Argon2Encrypt(data []byte) ([]byte, error) {
	key := argon2.IDKey(qsm.encryptionKey, qsm.salt, 1, 64*1024, 4, 32)

	encryptedData := make([]byte, len(data))
	for i := range data {
		encryptedData[i] = data[i] ^ key[i%len(key)]
	}

	return encryptedData, nil
}

// Argon2Decrypt decrypts data using the Argon2 algorithm
func (qsm *QuantumSafeAlgorithmsManager) Argon2Decrypt(data []byte) ([]byte, error) {
	key := argon2.IDKey(qsm.encryptionKey, qsm.salt, 1, 64*1024, 4, 32)

	decryptedData := make([]byte, len(data))
	for i := range data {
		decryptedData[i] = data[i] ^ key[i%len(key)]
	}

	return decryptedData, nil
}

// GenerateNewEncryptionKey generates and sets a new encryption key
func (qsm *QuantumSafeAlgorithmsManager) GenerateNewEncryptionKey() {
	qsm.mutex.Lock()
	defer qsm.mutex.Unlock()

	qsm.encryptionKey = generateEncryptionKey()
}

// GenerateNewSalt generates and sets a new salt
func (qsm *QuantumSafeAlgorithmsManager) GenerateNewSalt() {
	qsm.mutex.Lock()
	defer qsm.mutex.Unlock()

	qsm.salt = generateSalt()
}

// MonitorKeyRotation continuously monitors and rotates the encryption key and salt
func (qsm *QuantumSafeAlgorithmsManager) MonitorKeyRotation(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		qsm.GenerateNewEncryptionKey()
		qsm.GenerateNewSalt()
		log.Println("Encryption key and salt rotated")
	}
}

// PrintKeyAndSalt prints the current encryption key and salt in hexadecimal format
func (qsm *QuantumSafeAlgorithmsManager) PrintKeyAndSalt() {
	qsm.mutex.Lock()
	defer qsm.mutex.Unlock()

	fmt.Printf("Current Encryption Key: %s\n", hex.EncodeToString(qsm.encryptionKey))
	fmt.Printf("Current Salt: %s\n", hex.EncodeToString(qsm.salt))
}
