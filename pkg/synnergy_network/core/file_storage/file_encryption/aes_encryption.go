// Package file_encryption handles encryption and decryption of files using AES for the Synnergy Network blockchain.
package file_encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// AESCipher provides methods to encrypt and decrypt data using AES.
type AESCipher struct {
	Key []byte // AES requires keys to be 16, 24, or 32 bytes in length
}

// NewAESCipher creates a new AESCipher with a given key.
func NewAESCipher(key []byte) (*AESCipher, error) {
	switch len(key) {
	case 16, 24, 32:
		return &AESCipher{Key: key}, nil
	default:
		return nil, errors.New("invalid key size: must be 16, 24, or 32 bytes")
	}
}

// Encrypt encrypts data using AES-GCM.
func (ac *AESCipher) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(ac.Key)
	if err != nil {
		return nil, err
	}

	// GCM is an authenticated encryption mode that not only encrypts the data, but also provides a tag that can be used to verify the integrity and authenticity.
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Nonce should be unique for each operation with a given key.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal appends the result to the nonce.
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using AES-GCM.
func (ac *AESCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(ac.Key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Example of using AESCipher
func main() {
	key := []byte("thisis32bytekeythisis32bytekey") // Example key, should be securely generated and stored
	cipher, err := NewAESCipher(key)
	if err != nil {
		panic(err)
	}

	// Example encryption
	encrypted, err := cipher.Encrypt([]byte("exampleplaintext"))
	if err != nil {
		panic(err)
	}

	// Example decryption
	decrypted, err := cipher.Decrypt(encrypted)
	if err != nil {
		panic(err)
	}

	println("Decrypted text:", string(decrypted))
}
