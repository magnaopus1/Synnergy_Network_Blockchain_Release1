package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// SymmetricEncryption handles the encryption and decryption using symmetric key algorithms.
type SymmetricEncryption struct {
	Key []byte
}

// NewSymmetricEncryption creates a new instance of SymmetricEncryption with a randomly generated key.
func NewSymmetricEncryption(keySize int) (*SymmetricEncryption, error) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("error generating key: %v", err)
	}

	return &SymmetricEncryption{Key: key}, nil
}

// Encrypt encrypts data using AES encryption.
func (se *SymmetricEncryption) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(se.Key)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("error generating nonce: %v", err)
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

// Decrypt decrypts data using AES decryption.
func (se *SymmetricEncryption) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(se.Key)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	return decrypted, nil
}

// Example usage
func main() {
	encryptionHandler, err := NewSymmetricEncryption(32) // Using a 256-bit key for AES
	if err != nil {
		fmt.Println("Failed to initialize encryption handler:", err)
		return
	}

	// Example data to encrypt
	data := []byte("Sensitive data that needs to be encrypted")
	encryptedData, err := encryptionHandler.Encrypt(data)
	if err != nil {
		fmt.Println("Failed to encrypt data:", err)
		return
	}
	fmt.Println("Encrypted data:", encryptedData)

	decryptedData, err := encryptionHandler.Decrypt(encryptedData)
	if err != nil {
		fmt.Println("Failed to decrypt data:", err)
		return
	}
	fmt.Println("Decrypted data:", string(decryptedData))
}

// This code initializes an AES-GCM symmetric encryption scheme with secure key generation and nonce handling to ensure both confidentiality and authenticity of the data. It's well-suited for protecting transaction data within a blockchain context.
