package quantum_key_distribution

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// Constants for Argon2 and Scrypt
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
)

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

// SignData signs the data using the provided key
func SignData(data, key []byte) ([]byte, error) {
	hmac := GenerateHMAC(data, key)
	return hmac, nil
}

// VerifySignature verifies the signature of the data using the provided key
func VerifySignature(data, key, signature []byte) bool {
	return VerifyHMAC(data, key, signature)
}

// QuantumKeyManager manages quantum keys and their integrity verification
type QuantumKeyManager struct {
	keys map[string][]byte
}

// NewQuantumKeyManager creates a new QuantumKeyManager
func NewQuantumKeyManager() *QuantumKeyManager {
	return &QuantumKeyManager{
		keys: make(map[string][]byte),
	}
}

// AddKey adds a quantum key for a given chain ID
func (qm *QuantumKeyManager) AddKey(chainID string, password []byte) error {
	salt, err := GenerateRandomBytes(SaltLen)
	if err != nil {
		return err
	}

	key := GenerateArgon2Key(password, salt)
	qm.keys[chainID] = key
	return nil
}

// GetKey retrieves the quantum key for a given chain ID
func (qm *QuantumKeyManager) GetKey(chainID string) ([]byte, error) {
	key, exists := qm.keys[chainID]
	if !exists {
		return nil, errors.New("key not found")
	}
	return key, nil
}

// GenerateKeyPair generates a public-private key pair for quantum key distribution
func GenerateKeyPair() ([]byte, []byte, error) {
	privateKey, err := GenerateRandomBytes(Argon2KeyLen)
	if err != nil {
		return nil, nil, err
	}
	publicKey := sha256.Sum256(privateKey)
	return privateKey, publicKey[:], nil
}

// VerifyKeyPair verifies that a given public key matches the private key
func VerifyKeyPair(privateKey, publicKey []byte) bool {
	expectedPublicKey := sha256.Sum256(privateKey)
	return hmac.Equal(expectedPublicKey[:], publicKey)
}

// SecureKeyExchange exchanges keys securely using HMAC and SHA-256
func SecureKeyExchange(senderKey, receiverKey, data []byte) ([]byte, error) {
	hmac := GenerateHMAC(data, senderKey)
	if VerifyHMAC(data, receiverKey, hmac) {
		return hmac, nil
	}
	return nil, errors.New("key exchange verification failed")
}

// Test function to demonstrate the key management and integrity verification process
func main() {
	qkm := NewQuantumKeyManager()
	password := []byte("securepassword")
	chainID := "chain123"

	// Add a quantum key
	err := qkm.AddKey(chainID, password)
	if err != nil {
		fmt.Printf("Error adding key: %v\n", err)
		return
	}

	// Retrieve the quantum key
	key, err := qkm.GetKey(chainID)
	if err != nil {
		fmt.Printf("Error retrieving key: %v\n", err)
		return
	}
	fmt.Printf("Retrieved key: %s\n", hex.EncodeToString(key))

	// Sign data
	data := []byte("Important data")
	signature, err := SignData(data, key)
	if err != nil {
		fmt.Printf("Error signing data: %v\n", err)
		return
	}
	fmt.Printf("Data signature: %s\n", hex.EncodeToString(signature))

	// Verify signature
	isValid := VerifySignature(data, key, signature)
	fmt.Printf("Signature valid: %t\n", isValid)
}
