// Package node provides functionalities and services for the nodes within the Synnergy Network blockchain,
// including quantum-safe security implementations for real-world use.
package node

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
	"io"
)

// SecurityConfig holds configuration parameters for quantum-safe security.
type SecurityConfig struct {
	Argon2Time        uint32
	Argon2Memory      uint32
	Argon2Threads     uint8
	Argon2KeyLen      uint32
	ScryptN           int
	ScryptR           int
	ScryptP           int
	ScryptKeyLen      int
	EncryptionKeySize int
}

// DefaultSecurityConfig provides a default configuration for quantum-safe security.
var DefaultSecurityConfig = SecurityConfig{
	Argon2Time:        1,
	Argon2Memory:      64 * 1024,
	Argon2Threads:     4,
	Argon2KeyLen:      32,
	ScryptN:           32768,
	ScryptR:           8,
	ScryptP:           1,
	ScryptKeyLen:      32,
	EncryptionKeySize: 32,
}

// NodeSecurity represents the security functionalities of a node.
type NodeSecurity struct {
	config SecurityConfig
}

// NewNodeSecurity creates a new NodeSecurity instance with the specified configuration.
func NewNodeSecurity(config SecurityConfig) *NodeSecurity {
	return &NodeSecurity{config: config}
}

// GenerateSalt generates a new random salt.
func (ns *NodeSecurity) GenerateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// Argon2Hash generates an Argon2 hash for the given password and salt.
func (ns *NodeSecurity) Argon2Hash(password string, salt []byte) ([]byte, error) {
	hash := argon2.Key([]byte(password), salt, ns.config.Argon2Time, ns.config.Argon2Memory, ns.config.Argon2Threads, ns.config.Argon2KeyLen)
	return hash, nil
}

// ScryptHash generates a Scrypt hash for the given password and salt.
func (ns *NodeSecurity) ScryptHash(password string, salt []byte) ([]byte, error) {
	hash, err := scrypt.Key([]byte(password), salt, ns.config.ScryptN, ns.config.ScryptR, ns.config.ScryptP, ns.config.ScryptKeyLen)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

// Encrypt encrypts plaintext using AES-GCM with the specified key.
func (ns *NodeSecurity) Encrypt(plaintext, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext using AES-GCM with the specified key.
func (ns *NodeSecurity) Decrypt(ciphertextHex string, key []byte) ([]byte, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aesGCM.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:aesGCM.NonceSize()], ciphertext[aesGCM.NonceSize():]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Example usage:
// func main() {
// 	security := NewNodeSecurity(DefaultSecurityConfig)
// 	salt, err := security.GenerateSalt(16)
// 	if err != nil {
// 		log.Fatalf("Failed to generate salt: %v", err)
// 	}
//
// 	password := "example_password"
// 	hash, err := security.Argon2Hash(password, salt)
// 	if err != nil {
// 		log.Fatalf("Failed to generate Argon2 hash: %v", err)
// 	}
// 	fmt.Printf("Argon2 Hash: %x\n", hash)
//
// 	hash, err = security.ScryptHash(password, salt)
// 	if err != nil {
// 		log.Fatalf("Failed to generate Scrypt hash: %v", err)
// 	}
// 	fmt.Printf("Scrypt Hash: %x\n", hash)
//
// 	key := make([]byte, 32)
// 	if _, err = rand.Read(key); err != nil {
// 		log.Fatalf("Failed to generate encryption key: %v", err)
// 	}
// 	plaintext := []byte("example plaintext")
// 	ciphertext, err := security.Encrypt(plaintext, key)
// 	if err != nil {
// 		log.Fatalf("Failed to encrypt: %v", err)
// 	}
// 	fmt.Printf("Ciphertext: %s\n", ciphertext)
//
// 	decryptedText, err := security.Decrypt(ciphertext, key)
// 	if err != nil {
// 		log.Fatalf("Failed to decrypt: %v", err)
// 	}
// 	fmt.Printf("Decrypted Text: %s\n", decryptedText)
// }
