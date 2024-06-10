// Package file_encryption handles the comprehensive encryption and decryption of files within the Synnergy Network blockchain.
package file_encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// EndToEndEncryptor provides methods to encrypt and decrypt data securely from end to end.
type EndToEndEncryptor struct {
	Key []byte
}

// NewEndToEndEncryptor initializes a new EndToEndEncryptor with a provided key.
func NewEndToEndEncryptor(key []byte) (*EndToEndEncryptor, error) {
	if len(key) != 32 { // AES-256 requires a 32-byte key
		return nil, errors.New("invalid key size: must be 32 bytes for AES-256")
	}
	return &EndToEndEncryptor{Key: key}, nil
}

// Encrypt encrypts data using AES-GCM, providing confidentiality, integrity, and authenticity.
func (e *EndToEndEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.Key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts data using AES-GCM, ensuring the integrity and authenticity of the data.
func (e *EndToEndEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.Key)
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

// Example usage of EndToEndEncryptor
func main() {
	key := make([]byte, 32) // Generate a random 32-byte key for AES-256
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	encryptor, err := NewEndToEndEncryptor(key)
	if err != nil {
		panic(err)
	}

	// Example data encryption
	data := []byte("Sensitive data needing encryption")
	encryptedData, err := encryptor.Encrypt(data)
	if err != nil {
		panic(err)
	}

	// Example data decryption
	decryptedData, err := encryptor.Decrypt(encryptedData)
	if err != nil {
		panic(err)
	}

	println("Decrypted data:", string(decryptedData))
}
