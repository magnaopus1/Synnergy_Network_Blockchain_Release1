package quantum_key_distribution

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

const (
	Argon2Time        = 1
	Argon2Memory      = 64 * 1024
	Argon2Threads     = 4
	Argon2KeyLen      = 32
	ScryptN           = 32768
	ScryptR           = 8
	ScryptP           = 1
	ScryptKeyLen      = 32
	SaltLen           = 16
	HMACKeyLen        = 32
	AESKeyLen         = 32
)

// SecureKeyManager manages quantum keys and their lifecycle
type SecureKeyManager struct {
	keys map[string][]byte
	mu   sync.Mutex
}

// NewSecureKeyManager creates a new SecureKeyManager
func NewSecureKeyManager() *SecureKeyManager {
	return &SecureKeyManager{
		keys: make(map[string][]byte),
	}
}

// GenerateRandomBytes generates random bytes of specified length
func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// GenerateArgon2Key generates a key using the Argon2 algorithm
func GenerateArgon2Key(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
}

// GenerateScryptKey generates a key using the Scrypt algorithm
func GenerateScryptKey(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, ScryptN, ScryptR, ScryptP, ScryptKeyLen)
}

// Encrypt encrypts data using AES-GCM
func Encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, err := GenerateRandomBytes(aesGCM.NonceSize())
	if err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using AES-GCM
func Decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GenerateHMAC generates an HMAC for the given data using the provided key
func GenerateHMAC(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// VerifyHMAC verifies the HMAC of the given data using the provided key
func VerifyHMAC(data, key, hmacToCompare []byte) bool {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	expectedHMAC := h.Sum(nil)
	return hmac.Equal(expectedHMAC, hmacToCompare)
}

// AddKey adds a quantum key for a given chain ID
func (skm *SecureKeyManager) AddKey(chainID string, password []byte) error {
	salt, err := GenerateRandomBytes(SaltLen)
	if err != nil {
		return err
	}

	key := GenerateArgon2Key(password, salt)
	skm.mu.Lock()
	defer skm.mu.Unlock()
	skm.keys[chainID] = key
	return nil
}

// GetKey retrieves the quantum key for a given chain ID
func (skm *SecureKeyManager) GetKey(chainID string) ([]byte, error) {
	skm.mu.Lock()
	defer skm.mu.Unlock()
	key, exists := skm.keys[chainID]
	if !exists {
		return nil, errors.New("key not found")
	}
	return key, nil
}

// DeleteKey deletes the quantum key for a given chain ID
func (skm *SecureKeyManager) DeleteKey(chainID string) {
	skm.mu.Lock()
	defer skm.mu.Unlock()
	delete(skm.keys, chainID)
}

// UpdateKey updates the quantum key for a given chain ID
func (skm *SecureKeyManager) UpdateKey(chainID string, newPassword []byte) error {
	salt, err := GenerateRandomBytes(SaltLen)
	if err != nil {
		return err
	}

	key := GenerateArgon2Key(newPassword, salt)
	skm.mu.Lock()
	defer skm.mu.Unlock()
	skm.keys[chainID] = key
	return nil
}

// EncryptWithChainID encrypts data using the key for a given chain ID
func (skm *SecureKeyManager) EncryptWithChainID(chainID string, data []byte) ([]byte, error) {
	key, err := skm.GetKey(chainID)
	if err != nil {
		return nil, err
	}
	return Encrypt(data, key)
}

// DecryptWithChainID decrypts data using the key for a given chain ID
func (skm *SecureKeyManager) DecryptWithChainID(chainID string, data []byte) ([]byte, error) {
	key, err := skm.GetKey(chainID)
	if err != nil {
		return nil, err
	}
	return Decrypt(data, key)
}

// Test function to demonstrate the key management and encryption/decryption process
func main() {
	skm := NewSecureKeyManager()
	password := []byte("securepassword")
	chainID := "chain123"

	// Add a quantum key
	err := skm.AddKey(chainID, password)
	if err != nil {
		fmt.Printf("Error adding key: %v\n", err)
		return
	}

	// Retrieve the quantum key
	key, err := skm.GetKey(chainID)
	if err != nil {
		fmt.Printf("Error retrieving key: %v\n", err)
		return
	}
	fmt.Printf("Retrieved key: %s\n", hex.EncodeToString(key))

	// Encrypt data
	data := []byte("Sensitive blockchain data")
	ciphertext, err := skm.EncryptWithChainID(chainID, data)
	if err != nil {
		fmt.Printf("Error encrypting data: %v\n", err)
		return
	}
	fmt.Printf("Encrypted data: %s\n", hex.EncodeToString(ciphertext))

	// Decrypt data
	plaintext, err := skm.DecryptWithChainID(chainID, ciphertext)
	if err != nil {
		fmt.Printf("Error decrypting data: %v\n", err)
		return
	}
	fmt.Printf("Decrypted data: %s\n", plaintext)
}
