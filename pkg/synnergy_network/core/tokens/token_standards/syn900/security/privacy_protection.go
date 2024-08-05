package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"io"
	"strings"
)

// PrivacyProtection provides methods for managing privacy protection mechanisms
type PrivacyProtection struct {
	salt []byte
}

// NewPrivacyProtection initializes and returns a new PrivacyProtection instance with a generated salt
func NewPrivacyProtection() *PrivacyProtection {
	salt := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate salt: %v", err))
	}
	return &PrivacyProtection{salt: salt}
}

// EncryptData encrypts the provided data using AES-GCM with the given passphrase
func (pp *PrivacyProtection) EncryptData(data, passphrase string) (string, error) {
	key, err := deriveKey(passphrase, pp.salt)
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

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)

	return encodedCiphertext, nil
}

// DecryptData decrypts the provided data using AES-GCM with the given passphrase
func (pp *PrivacyProtection) DecryptData(encryptedData, passphrase string) (string, error) {
	key, err := deriveKey(passphrase, pp.salt)
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

	decodedCiphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(decodedCiphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := decodedCiphertext[:nonceSize], decodedCiphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// AnonymizeData anonymizes certain data points while preserving verifiability
func (pp *PrivacyProtection) AnonymizeData(data map[string]string, fieldsToAnonymize []string) map[string]string {
	anonymizedData := make(map[string]string)
	for key, value := range data {
		if contains(fieldsToAnonymize, key) {
			anonymizedData[key] = hashData(value)
		} else {
			anonymizedData[key] = value
		}
	}
	return anonymizedData
}

// Contains checks if a slice contains a specific element
func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

// HashData returns a SHA-256 hash of the input data
func hashData(data string) string {
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// deriveKey derives a key from the given passphrase and salt using scrypt
func deriveKey(passphrase string, salt []byte) ([]byte, error) {
	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// SetSalt allows setting a custom salt for key derivation
func (pp *PrivacyProtection) SetSalt(salt []byte) error {
	if len(salt) != 16 {
		return errors.New("invalid salt size")
	}
	pp.salt = salt
	return nil
}

// GetSalt returns the current salt used for key derivation
func (pp *PrivacyProtection) GetSalt() []byte {
	return pp.salt
}

// SelectiveDisclosure enables users to disclose only specific parts of their identity data
func (pp *PrivacyProtection) SelectiveDisclosure(data map[string]string, fieldsToDisclose []string) map[string]string {
	disclosedData := make(map[string]string)
	for _, field := range fieldsToDisclose {
		if value, exists := data[field]; exists {
			disclosedData[field] = value
		}
	}
	return disclosedData
}

// ConsentManagement provides methods for managing user consent
type ConsentManagement struct {
	consentRecords map[string]bool
}

// NewConsentManagement initializes and returns a new ConsentManagement instance
func NewConsentManagement() *ConsentManagement {
	return &ConsentManagement{consentRecords: make(map[string]bool)}
}

// GrantConsent grants consent for a specific operation
func (cm *ConsentManagement) GrantConsent(operation string) {
	cm.consentRecords[operation] = true
}

// RevokeConsent revokes consent for a specific operation
func (cm *ConsentManagement) RevokeConsent(operation string) {
	cm.consentRecords[operation] = false
}

// HasConsent checks if consent has been granted for a specific operation
func (cm *ConsentManagement) HasConsent(operation string) bool {
	return cm.consentRecords[operation]
}

// ZeroKnowledgeProofs provides methods for zero-knowledge proof techniques
type ZeroKnowledgeProofs struct {
	// Implement zero-knowledge proof functionalities as needed
}

// NewZeroKnowledgeProofs initializes and returns a new ZeroKnowledgeProofs instance
func NewZeroKnowledgeProofs() *ZeroKnowledgeProofs {
	return &ZeroKnowledgeProofs{}
}

// GenerateProof generates a zero-knowledge proof for a given attribute
func (zkp *ZeroKnowledgeProofs) GenerateProof(attribute string) string {
	// Placeholder for zero-knowledge proof generation logic
	return hashData(attribute)
}

// VerifyProof verifies a zero-knowledge proof for a given attribute
func (zkp *ZeroKnowledgeProofs) VerifyProof(attribute, proof string) bool {
	// Placeholder for zero-knowledge proof verification logic
	expectedProof := hashData(attribute)
	return strings.EqualFold(expectedProof, proof)
}
