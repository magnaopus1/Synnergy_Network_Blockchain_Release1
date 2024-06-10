// Package file_encryption manages the encryption access based on user roles within the Synnergy Network blockchain.
package file_encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

// RoleBasedAccessManager controls access to encrypted data based on predefined roles.
type RoleBasedAccessManager struct {
	KeyStore map[string][]byte // Map of role to encryption keys
}

// NewRoleBasedAccessManager initializes a RoleBasedAccessManager with an empty keystore.
func NewRoleBasedAccessManager() *RoleBasedAccessManager {
	return &RoleBasedAccessManager{
		KeyStore: make(map[string][]byte),
	}
}

// AddRoleKey adds a new role and corresponding key to the manager.
func (rbam *RoleBasedAccessManager) AddRoleKey(role string, key []byte) {
	rbam.KeyStore[role] = key
}

// GenerateKey generates a new AES key for a specific role.
func (rbam *RoleBasedAccessManager) GenerateKey() ([]byte, error) {
	key := make([]byte, 32) // AES-256 requires a 32-byte key
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptData encrypts data for a specific role using AES-GCM.
func (rbam *RoleBasedAccessManager) EncryptData(role string, plaintext []byte) ([]byte, error) {
	key, ok := rbam.KeyStore[role]
	if !ok {
		return nil, errors.New("role key not found")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptData decrypts data for a specific role using AES-GCM.
func (rbam *RoleBasedAccessManager) DecryptData(role string, ciphertext []byte) ([]byte, error) {
	key, ok := rbam.KeyStore[role]
	if !ok {
		return nil, errors.New("role key not found")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aesgcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:aesgcm.NonceSize()], ciphertext[aesgcm.NonceSize():]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Example usage of RoleBasedAccessManager.
func main() {
	manager := NewRoleBasedAccessManager()
	role := "admin"

	// Generating a key for the role
	key, err := manager.GenerateKey()
	if err != nil {
		panic(err)
	}
	manager.AddRoleKey(role, key)

	// Example data to encrypt and decrypt
	data := []byte("Sensitive data for role-based access")
	encryptedData, err := manager.EncryptData(role, data)
	if err != nil {
		panic(err)
	}

	decryptedData, err := manager.DecryptData(role, encryptedData)
	if err != nil {
		panic(err)
	}

	println("Decrypted data:", string(decryptedData))
}
