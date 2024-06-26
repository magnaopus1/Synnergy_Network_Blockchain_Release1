package hybrid_cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/argon2"
)

// DualLayerSecurity provides a two-layer security system combining classical and quantum-resistant algorithms.
type DualLayerSecurity struct {
	ClassicalKey      []byte
	QuantumResistantKey []byte
}

// NewDualLayerSecurity initializes a new instance of DualLayerSecurity with the provided keys.
func NewDualLayerSecurity(classicalKey, quantumResistantKey []byte) *DualLayerSecurity {
	return &DualLayerSecurity{
		ClassicalKey:      classicalKey,
		QuantumResistantKey: quantumResistantKey,
	}
}

// GenerateClassicalKey generates a classical cryptographic key using Scrypt.
func GenerateClassicalKey(password, salt []byte) ([]byte, error) {
	dk, err := scrypt.Key(password, salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return dk, nil
}

// GenerateQuantumResistantKey generates a quantum-resistant cryptographic key using Argon2.
func GenerateQuantumResistantKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// Encrypt encrypts data using dual-layer security.
func (dls *DualLayerSecurity) Encrypt(plaintext []byte) (string, error) {
	// Classical Encryption (AES)
	block, err := aes.NewCipher(dls.ClassicalKey)
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

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Quantum-Resistant Encryption (SHA-256)
	hash := sha256.Sum256(append(dls.QuantumResistantKey, ciphertext...))
	finalCiphertext := append(ciphertext, hash[:]...)

	return hex.EncodeToString(finalCiphertext), nil
}

// Decrypt decrypts data using dual-layer security.
func (dls *DualLayerSecurity) Decrypt(encodedCiphertext string) ([]byte, error) {
	finalCiphertext, err := hex.DecodeString(encodedCiphertext)
	if err != nil {
		return nil, err
	}

	// Extract components
	hashSize := sha256.Size
	ciphertext := finalCiphertext[:len(finalCiphertext)-hashSize]
	expectedHash := finalCiphertext[len(finalCiphertext)-hashSize:]

	// Verify Quantum-Resistant Hash
	actualHash := sha256.Sum256(append(dls.QuantumResistantKey, ciphertext...))
	if !bytes.Equal(expectedHash, actualHash[:]) {
		return nil, errors.New("invalid ciphertext: quantum-resistant hash mismatch")
	}

	// Classical Decryption (AES)
	block, err := aes.NewCipher(dls.ClassicalKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("invalid ciphertext: too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Example usage
func main() {
	password := []byte("securepassword")
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}

	classicalKey, err := GenerateClassicalKey(password, salt)
	if err != nil {
		panic(err)
	}

	quantumResistantKey := GenerateQuantumResistantKey(password, salt)

	dls := NewDualLayerSecurity(classicalKey, quantumResistantKey)

	message := []byte("Hello, Quantum-Resistant World!")
	encryptedMessage, err := dls.Encrypt(message)
	if err != nil {
		panic(err)
	}
	
	decryptedMessage, err := dls.Decrypt(encryptedMessage)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(message, decryptedMessage) {
		panic("Decrypted message does not match original")
	}

	fmt.Println("Encryption and Decryption successful")
}
