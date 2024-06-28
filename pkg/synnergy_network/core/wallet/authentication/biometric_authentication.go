package authentication

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/synnergy-network/blockchain/crypto"
	"github.com/synnergy-network/blockchain/utils"
	"golang.org/x/crypto/bcrypt"
)

// BiometricData represents the user's biometric data.
type BiometricData struct {
	UserID      string
	Template    []byte
	LastUpdated time.Time
}

// BiometricDatabase simulates a database of biometric data.
var BiometricDatabase = map[string]*BiometricData{}

// GenerateBiometricTemplate simulates the generation of a biometric template from a sample.
func GenerateBiometricTemplate(sample []byte) ([]byte, error) {
	if len(sample) == 0 {
		return nil, errors.New("biometric sample is empty")
	}

	hasher := sha256.New()
	_, err := hasher.Write(sample)
	if err != nil {
		return nil, fmt.Errorf("failed to hash biometric sample: %w", err)
	}

	return hasher.Sum(nil), nil
}

// SaveBiometricData saves the user's biometric template in the simulated database.
func SaveBiometricData(userID string, template []byte) error {
	if userID == "" {
		return errors.New("user ID cannot be empty")
	}
	if len(template) == 0 {
		return errors.New("biometric template is empty")
	}

	BiometricDatabase[userID] = &BiometricData{
		UserID:      userID,
		Template:    template,
		LastUpdated: time.Now(),
	}
	return nil
}

// AuthenticateUser authenticates a user based on biometric data sample.
func AuthenticateUser(userID string, sample []byte) (bool, error) {
	storedData, exists := BiometricDatabase[userID]
	if !exists {
		return false, fmt.Errorf("no biometric data found for user ID %s", userID)
	}

	generatedTemplate, err := GenerateBiometricTemplate(sample)
	if err != nil {
		return false, fmt.Errorf("failed to generate biometric template: %w", err)
	}

	err = bcrypt.CompareHashAndPassword(storedData.Template, generatedTemplate)
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil // authentication failure
		}
		return false, fmt.Errorf("error comparing biometric data: %w", err)
	}

	return true, nil // authentication success
}

// EncryptTemplate encrypts the biometric template using AES.
func EncryptTemplate(template []byte) ([]byte, error) {
	secretKey := []byte(os.Getenv("BIOMETRIC_SECRET_KEY")) // Secret key from environment variable
	if len(secretKey) == 0 {
		return nil, errors.New("secret key is not set for biometric encryption")
	}

	encryptedData, err := crypto.AES256Encrypt(template, secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt biometric template: %w", err)
	}

	return encryptedData, nil
}

// DecryptTemplate decrypts the biometric template using AES.
func DecryptTemplate(encryptedData []byte) ([]byte, error) {
	secretKey := []byte(os.Getenv("BIOMETRIC_SECRET_KEY")) // Secret key from environment variable
	if len(secretKey) == 0 {
		return nil, errors.New("secret key is not set for biometric decryption")
	}

	decryptedData, err := crypto.AES256Decrypt(encryptedData, secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt biometric template: %w", err)
	}

	return decryptedData, nil
}

// EncodeTemplateToBase64 encodes biometric data to a base64 string for storage.
func EncodeTemplateToBase64(data []byte) (string, error) {
	if len(data) == 0 {
		return "", errors.New("cannot encode empty biometric data to base64")
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

// DecodeTemplateFromBase64 decodes biometric data from a base64 string.
func DecodeTemplateFromBase64(encodedData string) ([]byte, error) {
	if encodedData == "" {
		return nil, errors.New("base64 string is empty")
	}

	data, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode biometric data from base64: %w", err)
	}

	return data, nil
}

