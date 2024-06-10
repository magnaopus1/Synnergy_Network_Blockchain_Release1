package iot_interface

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/pkg/errors"
)

// IoTBlockchainInterface facilitates communication between IoT devices and the blockchain.
type IoTBlockchainInterface struct {
	encryptionKey []byte
}

// NewIoTBlockchainInterface creates a new interface with a secure random key.
func NewIoTBlockchainInterface() (*IoTBlockchainInterface, error) {
	key := make([]byte, 32) // Using AES-256
	if _, err := rand.Read(key); err != nil {
		return nil, errors.Wrap(err, "failed to generate a secure key")
	}
	return &IoTBlockchainInterface{encryptionKey: key}, nil
}

// EncryptData encrypts data using AES-256 GCM before sending it to the blockchain.
func (ibi *IoTBlockchainInterface) EncryptData(data []byte) (string, error) {
	block, err := aes.NewCipher(ibi.encryptionKey)
	if err != nil {
		return "", errors.Wrap(err, "failed to create cipher")
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.Wrap(err, "failed to create GCM")
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", errors.Wrap(err, "failed to generate nonce")
	}

	encrypted := aesGCM.Seal(nonce, nonce, data, nil)
	return base64.URLEncoding.EncodeToString(encrypted), nil
}

// DecryptData decrypts data received from the blockchain.
func (ibi *IoTBlockchainInterface) DecryptData(encryptedData string) ([]byte, error) {
	data, err := base64.URLEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode data")
	}

	block, err := aes.NewCipher(ibi.encryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cipher")
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM")
	}

	if len(data) < aesGCM.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	nonce, ciphertext := data[:aesGCM.NonceSize()], data[aesGCM.NonceSize():]
	decrypted, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt data")
	}

	return decrypted, nil
}

// Example usage and function testing should be included to validate the features.
