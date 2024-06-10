// Package file_retrieval implements secure direct download links for the Synnergy Network blockchain.
package file_retrieval

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"time"
)

// SecureLinkManager manages the creation and validation of secure direct download links.
type SecureLinkManager struct {
	key []byte // AES key for encrypting and decrypting download tokens
}

// NewSecureLinkManager initializes a new SecureLinkManager with a specified AES key.
func NewSecureLinkManager(key []byte) *SecureLinkManager {
	return &SecureLinkManager{key: key}
}

// GenerateSecureLink generates a secure, time-limited download link for a file.
func (slm *SecureLinkManager) GenerateSecureLink(fileID string, duration time.Duration) (string, error) {
	expires := time.Now().Add(duration).Unix()
	token := fileID + "|" + string(expires)
	encryptedToken, err := slm.encrypt([]byte(token))
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(encryptedToken), nil
}

// ValidateSecureLink checks if a download link is valid and returns the fileID if it is.
func (slm *SecureLinkManager) ValidateSecureLink(encodedToken string) (string, error) {
	data, err := base64.URLEncoding.DecodeString(encodedToken)
	if err != nil {
		return "", err
	}

	decryptedToken, err := slm.decrypt(data)
	if err != nil {
		return "", err
	}

	parts := string(decryptedToken).split("|")
	if len(parts) != 2 {
		return "", errors.New("invalid token format")
	}

	expiration, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > expiration {
		return "", errors.New("token expired or invalid")
	}

	return parts[0], nil
}

// encrypt encrypts data using AES-GCM.
func (slm *SecureLinkManager) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(slm.key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decrypt decrypts data using AES-GCM.
func (slm *SecureLinkManager) decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(slm.key)
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

// Example usage and setup
func main() {
	key := make([]byte, 32) // 256-bit key for AES
	if _, err := rand.Read(key); err != nil {
		panic("key generation failed")
	}

	slm := NewSecureLinkManager(key)
	link, err := slm.GenerateSecureLink("file123", 24*time.Hour)
	if err != nil {
		panic("failed to generate secure link")
	}

	fileID, err := slm.ValidateSecureLink(link)
	if err != nil {
		fmt.Println("failed to validate link:", err)
	} else {
		fmt.Println("validated link for file:", fileID)
	}
}
