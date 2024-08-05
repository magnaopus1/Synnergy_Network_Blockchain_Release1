package computing_resource_marketplace

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"time"
)

// Utility functions for the computing resource marketplace

// GenerateSalt creates a new random salt.
func GenerateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}
	return salt, nil
}

// HashPassword hashes a password with a given salt using SHA-256.
func HashPassword(password string, salt []byte) string {
	hash := sha256.New()
	hash.Write([]byte(password))
	hash.Write(salt)
	return hex.EncodeToString(hash.Sum(nil))
}

// EncryptData encrypts data using AES encryption.
func EncryptData(data, passphrase string) (string, error) {
	block, err := aes.NewCipher([]byte(createHash(passphrase)))
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to create nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts AES-encrypted data.
func DecryptData(encryptedData, passphrase string) (string, error) {
	data, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode data: %v", err)
	}

	block, err := aes.NewCipher([]byte(createHash(passphrase)))
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data: %v", err)
	}

	return string(plaintext), nil
}

// createHash creates a hash of the passphrase using SHA-256.
func createHash(passphrase string) string {
	hash := sha256.New()
	hash.Write([]byte(passphrase))
	return hex.EncodeToString(hash.Sum(nil))
}

// ResourceAllocation represents the allocation of computing resources.
type ResourceAllocation struct {
	ResourceID    string
	UserID        string
	AllocatedAt   time.Time
	Duration      time.Duration
	ResourcesUsed map[string]float64 // e.g., {"CPU": 2.5, "Memory": 8.0}
}

// ResourceManager manages resource allocations.
type ResourceManager struct {
	allocations []ResourceAllocation
}

// NewResourceManager creates a new ResourceManager.
func NewResourceManager() *ResourceManager {
	return &ResourceManager{
		allocations: []ResourceAllocation{},
	}
}

// AllocateResources allocates resources to a user.
func (rm *ResourceManager) AllocateResources(resourceID, userID string, duration time.Duration, resourcesUsed map[string]float64) {
	allocation := ResourceAllocation{
		ResourceID:    resourceID,
		UserID:        userID,
		AllocatedAt:   time.Now(),
		Duration:      duration,
		ResourcesUsed: resourcesUsed,
	}
	rm.allocations = append(rm.allocations, allocation)
	log.Printf("Allocated resources: %v to user: %s\n", resourcesUsed, userID)
}

// ReleaseResources releases allocated resources.
func (rm *ResourceManager) ReleaseResources(resourceID, userID string) {
	for i, allocation := range rm.allocations {
		if allocation.ResourceID == resourceID && allocation.UserID == userID {
			rm.allocations = append(rm.allocations[:i], rm.allocations[i+1:]...)
			log.Printf("Released resources: %v from user: %s\n", allocation.ResourcesUsed, userID)
			return
		}
	}
	log.Printf("No resources found to release for resource ID: %s and user ID: %s\n", resourceID, userID)
}

// GetAllocations returns all current resource allocations.
func (rm *ResourceManager) GetAllocations() []ResourceAllocation {
	return rm.allocations
}

// ValidateResourceUsage validates the usage of resources based on predefined rules.
func ValidateResourceUsage(resourcesUsed map[string]float64) bool {
	// Example validation logic
	for resource, usage := range resourcesUsed {
		if usage < 0 {
			log.Printf("Invalid resource usage: %s usage cannot be negative\n", resource)
			return false
		}
	}
	return true
}
