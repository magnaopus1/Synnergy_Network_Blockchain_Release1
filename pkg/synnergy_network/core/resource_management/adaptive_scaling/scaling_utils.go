package adaptive_scaling

import (
	"crypto/rand"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/argon2"
)

// ScalingUtils provides utility functions for scaling and resource management
type ScalingUtils struct {
	mu sync.Mutex
}

// GenerateNodeID generates a secure and unique node ID
func (su *ScalingUtils) GenerateNodeID() (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("node-%x", randomBytes), nil
}

// EncryptData securely encrypts data using AES
func (su *ScalingUtils) EncryptData(plainText, password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptData securely decrypts data using AES
func (su *ScalingUtils) DecryptData(encryptedText, password string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	salt := ciphertext[:16]
	ciphertext = ciphertext[16:]

	key, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

// ComputeHash generates a hash using SHA-256
func (su *ScalingUtils) ComputeHash(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// MonitorResources monitors system resources and triggers scaling actions
func (su *ScalingUtils) MonitorResources(thresholds ResourceThresholds, action func()) {
	for {
		cpuUsage, memoryUsage, networkUsage := su.getSystemUsage()
		if cpuUsage > thresholds.CPUUtilizationHigh || memoryUsage > thresholds.MemoryUtilizationHigh || networkUsage > thresholds.NetworkUtilizationHigh {
			action()
		}
		time.Sleep(time.Minute)
	}
}

// getSystemUsage simulates system resource usage retrieval
func (su *ScalingUtils) getSystemUsage() (float64, float64, float64) {
	// Implement actual resource monitoring logic here
	// Returning dummy values for now
	return 75.0, 65.0, 50.0
}

// AdaptiveWaitTime calculates an adaptive wait time based on system load
func (su *ScalingUtils) AdaptiveWaitTime(baseTime time.Duration, loadFactor float64) time.Duration {
	// Adaptive wait time reduces as load factor increases to speed up scaling actions
	return time.Duration(float64(baseTime) * (1.0 - loadFactor/100.0))
}

// SecurePasswordHash hashes passwords using Argon2
func (su *ScalingUtils) SecurePasswordHash(password string, salt []byte) (string, error) {
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return base64.StdEncoding.EncodeToString(hash), nil
}

// ValidatePasswordHash validates a password against a stored hash
func (su *ScalingUtils) ValidatePasswordHash(password, hash string, salt []byte) (bool, error) {
	computedHash, err := su.SecurePasswordHash(password, salt)
	if err != nil {
		return false, err
	}
	return computedHash == hash, nil
}

// GenerateSalt generates a cryptographically secure salt
func (su *ScalingUtils) GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// LogAndAlert logs an event and triggers an alert if necessary
func (su *ScalingUtils) LogAndAlert(message string, alert bool) {
	log.Println(message)
	if alert {
		// Implement alerting mechanism, e.g., sending an email or SMS notification
	}
}
