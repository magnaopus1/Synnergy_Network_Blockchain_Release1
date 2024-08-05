package privacy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"time"
)

// ObfuscatedAddress represents an address that has been obfuscated for privacy
type ObfuscatedAddress struct {
	OriginalAddress string
	ObfuscatedData  string
	Timestamp       time.Time
}

// ObfuscationManager manages the obfuscation and deobfuscation of addresses
type ObfuscationManager struct {
	encryptionKey string
}

// NewObfuscationManager initializes a new ObfuscationManager with an encryption key
func NewObfuscationManager(encryptionKey string) *ObfuscationManager {
	return &ObfuscationManager{
		encryptionKey: encryptionKey,
	}
}

// ObfuscateAddress obfuscates the given address using AES encryption
func (om *ObfuscationManager) ObfuscateAddress(address string) (ObfuscatedAddress, error) {
	timestamp := time.Now()
	encryptedData, err := om.encryptData(address, timestamp)
	if err != nil {
		return ObfuscatedAddress{}, err
	}

	obfuscatedAddress := ObfuscatedAddress{
		OriginalAddress: address,
		ObfuscatedData:  encryptedData,
		Timestamp:       timestamp,
	}

	return obfuscatedAddress, nil
}

// DeobfuscateAddress deobfuscates the given obfuscated address using AES decryption
func (om *ObfuscationManager) DeobfuscateAddress(obfuscatedAddress ObfuscatedAddress) (string, error) {
	decryptedData, err := om.decryptData(obfuscatedAddress.ObfuscatedData, obfuscatedAddress.Timestamp)
	if err != nil {
		return "", err
	}

	return decryptedData, nil
}

// encryptData encrypts the data using AES with the given timestamp as a nonce
func (om *ObfuscationManager) encryptData(data string, timestamp time.Time) (string, error) {
	block, err := aes.NewCipher([]byte(om.generateKey()))
	if err != nil {
		return "", err
	}

	nonce := om.generateNonce(timestamp)
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nil, nonce, []byte(data), nil)
	return hex.EncodeToString(ciphertext), nil
}

// decryptData decrypts the data using AES with the given timestamp as a nonce
func (om *ObfuscationManager) decryptData(encryptedData string, timestamp time.Time) (string, error) {
	block, err := aes.NewCipher([]byte(om.generateKey()))
	if err != nil {
		return "", err
	}

	nonce := om.generateNonce(timestamp)
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// generateKey generates a SHA-256 hash of the encryption key
func (om *ObfuscationManager) generateKey() string {
	hash := sha256.New()
	hash.Write([]byte(om.encryptionKey))
	return hex.EncodeToString(hash.Sum(nil))[:32]
}

// generateNonce generates a nonce using the timestamp
func (om *ObfuscationManager) generateNonce(timestamp time.Time) []byte {
	hash := sha256.New()
	hash.Write([]byte(timestamp.String()))
	return hash.Sum(nil)[:12]
}

// ObfuscationService provides a higher-level interface for managing obfuscated addresses
type ObfuscationService struct {
	manager *ObfuscationManager
	cache   map[string]ObfuscatedAddress
}

// NewObfuscationService initializes a new ObfuscationService with an encryption key
func NewObfuscationService(encryptionKey string) *ObfuscationService {
	return &ObfuscationService{
		manager: NewObfuscationManager(encryptionKey),
		cache:   make(map[string]ObfuscatedAddress),
	}
}

// ObfuscateAndCacheAddress obfuscates an address and caches the result
func (os *ObfuscationService) ObfuscateAndCacheAddress(address string) (ObfuscatedAddress, error) {
	obfuscatedAddress, err := os.manager.ObfuscateAddress(address)
	if err != nil {
		return ObfuscatedAddress{}, err
	}
	os.cache[address] = obfuscatedAddress
	return obfuscatedAddress, nil
}

// GetCachedObfuscatedAddress retrieves an obfuscated address from the cache
func (os *ObfuscationService) GetCachedObfuscatedAddress(address string) (ObfuscatedAddress, error) {
	obfuscatedAddress, exists := os.cache[address]
	if !exists {
		return ObfuscatedAddress{}, errors.New("obfuscated address not found in cache")
	}
	return obfuscatedAddress, nil
}

// DeobfuscateCachedAddress deobfuscates an address from the cache
func (os *ObfuscationService) DeobfuscateCachedAddress(address string) (string, error) {
	obfuscatedAddress, err := os.GetCachedObfuscatedAddress(address)
	if err != nil {
		return "", err
	}
	return os.manager.DeobfuscateAddress(obfuscatedAddress)
}

// GenerateRandomKey generates a random encryption key for obfuscation
func GenerateRandomKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}
