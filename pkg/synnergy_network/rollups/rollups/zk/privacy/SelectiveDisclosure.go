package privacy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"
)

// SelectiveDisclosure represents the structure for selectively disclosing information.
type SelectiveDisclosure struct {
	OriginalData      string
	DisclosedData     string
	EncryptedData     string
	DisclosurePolicy  DisclosurePolicy
	Timestamp         time.Time
}

// DisclosurePolicy defines the rules for what data can be disclosed.
type DisclosurePolicy struct {
	AllowedFields []string
}

// SelectiveDisclosureManager manages the selective disclosure of data.
type SelectiveDisclosureManager struct {
	encryptionKey string
}

// NewSelectiveDisclosureManager initializes a new SelectiveDisclosureManager with an encryption key.
func NewSelectiveDisclosureManager(encryptionKey string) *SelectiveDisclosureManager {
	return &SelectiveDisclosureManager{
		encryptionKey: encryptionKey,
	}
}

// CreateSelectiveDisclosure creates a selectively disclosed version of the data based on the policy.
func (sdm *SelectiveDisclosureManager) CreateSelectiveDisclosure(data string, policy DisclosurePolicy) (SelectiveDisclosure, error) {
	timestamp := time.Now()
	encryptedData, err := sdm.encryptData(data, timestamp)
	if err != nil {
		return SelectiveDisclosure{}, err
	}

	disclosedData, err := sdm.applyPolicy(data, policy)
	if err != nil {
		return SelectiveDisclosure{}, err
	}

	selectiveDisclosure := SelectiveDisclosure{
		OriginalData:      data,
		DisclosedData:     disclosedData,
		EncryptedData:     encryptedData,
		DisclosurePolicy:  policy,
		Timestamp:         timestamp,
	}

	return selectiveDisclosure, nil
}

// VerifySelectiveDisclosure verifies the disclosed data against the original data.
func (sdm *SelectiveDisclosureManager) VerifySelectiveDisclosure(selectiveDisclosure SelectiveDisclosure) (bool, error) {
	decryptedData, err := sdm.decryptData(selectiveDisclosure.EncryptedData, selectiveDisclosure.Timestamp)
	if err != nil {
		return false, err
	}

	disclosedData, err := sdm.applyPolicy(decryptedData, selectiveDisclosure.DisclosurePolicy)
	if err != nil {
		return false, err
	}

	return disclosedData == selectiveDisclosure.DisclosedData, nil
}

// encryptData encrypts the data using AES with the given timestamp as a nonce.
func (sdm *SelectiveDisclosureManager) encryptData(data string, timestamp time.Time) (string, error) {
	block, err := aes.NewCipher([]byte(sdm.generateKey()))
	if err != nil {
		return "", err
	}

	nonce := sdm.generateNonce(timestamp)
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nil, nonce, []byte(data), nil)
	return hex.EncodeToString(ciphertext), nil
}

// decryptData decrypts the data using AES with the given timestamp as a nonce.
func (sdm *SelectiveDisclosureManager) decryptData(encryptedData string, timestamp time.Time) (string, error) {
	block, err := aes.NewCipher([]byte(sdm.generateKey()))
	if err != nil {
		return "", err
	}

	nonce := sdm.generateNonce(timestamp)
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

// generateKey generates a SHA-256 hash of the encryption key.
func (sdm *SelectiveDisclosureManager) generateKey() string {
	hash := sha256.New()
	hash.Write([]byte(sdm.encryptionKey))
	return hex.EncodeToString(hash.Sum(nil))[:32]
}

// generateNonce generates a nonce using the timestamp.
func (sdm *SelectiveDisclosureManager) generateNonce(timestamp time.Time) []byte {
	hash := sha256.New()
	hash.Write([]byte(timestamp.String()))
	return hash.Sum(nil)[:12]
}

// applyPolicy applies the disclosure policy to the data and returns the disclosed data.
func (sdm *SelectiveDisclosureManager) applyPolicy(data string, policy DisclosurePolicy) (string, error) {
	disclosedData := ""
	// Logic to apply policy to data
	// For simplicity, let's assume data is a JSON string and policy contains allowed fields.
	// Parse the JSON and only keep the allowed fields.
	// This is a placeholder logic, needs to be implemented based on actual data structure.

	// Example placeholder logic:
	// jsonData := map[string]interface{}{}
	// err := json.Unmarshal([]byte(data), &jsonData)
	// if err != nil {
	// 	return "", err
	// }
	// filteredData := map[string]interface{}{}
	// for _, field := range policy.AllowedFields {
	// 	if value, ok := jsonData[field]; ok {
	// 		filteredData[field] = value
	// 	}
	// }
	// filteredDataBytes, err := json.Marshal(filteredData)
	// if err != nil {
	// 	return "", err
	// }
	// disclosedData = string(filteredDataBytes)

	return disclosedData, nil
}

// SelectiveDisclosureService provides a higher-level interface for managing selective disclosure.
type SelectiveDisclosureService struct {
	manager *SelectiveDisclosureManager
	cache   map[string]SelectiveDisclosure
}

// NewSelectiveDisclosureService initializes a new SelectiveDisclosureService with an encryption key.
func NewSelectiveDisclosureService(encryptionKey string) *SelectiveDisclosureService {
	return &SelectiveDisclosureService{
		manager: NewSelectiveDisclosureManager(encryptionKey),
		cache:   make(map[string]SelectiveDisclosure),
	}
}

// CreateAndCacheSelectiveDisclosure creates a selectively disclosed version of the data and caches the result.
func (sds *SelectiveDisclosureService) CreateAndCacheSelectiveDisclosure(data string, policy DisclosurePolicy) (SelectiveDisclosure, error) {
	selectiveDisclosure, err := sds.manager.CreateSelectiveDisclosure(data, policy)
	if err != nil {
		return SelectiveDisclosure{}, err
	}
	sds.cache[data] = selectiveDisclosure
	return selectiveDisclosure, nil
}

// GetCachedSelectiveDisclosure retrieves a selectively disclosed version of the data from the cache.
func (sds *SelectiveDisclosureService) GetCachedSelectiveDisclosure(data string) (SelectiveDisclosure, error) {
	selectiveDisclosure, exists := sds.cache[data]
	if !exists {
		return SelectiveDisclosure{}, errors.New("selective disclosure not found in cache")
	}
	return selectiveDisclosure, nil
}

// VerifyCachedSelectiveDisclosure verifies the disclosed data against the original data in the cache.
func (sds *SelectiveDisclosureService) VerifyCachedSelectiveDisclosure(data string) (bool, error) {
	selectiveDisclosure, err := sds.GetCachedSelectiveDisclosure(data)
	if err != nil {
		return false, err
	}
	return sds.manager.VerifySelectiveDisclosure(selectiveDisclosure)
}

// GenerateRandomKey generates a random encryption key for selective disclosure.
func GenerateRandomKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}
