package upgrades

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// FeatureIntegration provides methods for managing feature upgrades in the blockchain network
type FeatureIntegration struct {
	FeatureSet map[string]bool
	APIKey     string
	SecretKey  string
	Mutex      sync.Mutex
}

// NewFeatureIntegration creates a new instance of FeatureIntegration
func NewFeatureIntegration(apiKey, secretKey string) *FeatureIntegration {
	return &FeatureIntegration{
		FeatureSet: make(map[string]bool),
		APIKey:     apiKey,
		SecretKey:  secretKey,
	}
}

// EnableFeature enables a new feature in the blockchain network
func (fi *FeatureIntegration) EnableFeature(featureName string) error {
	fi.Mutex.Lock()
	defer fi.Mutex.Unlock()

	if _, exists := fi.FeatureSet[featureName]; exists {
		return fmt.Errorf("feature %s already enabled", featureName)
	}

	fi.FeatureSet[featureName] = true
	fi.logFeatureActivity("enable", featureName)
	return nil
}

// DisableFeature disables a feature in the blockchain network
func (fi *FeatureIntegration) DisableFeature(featureName string) error {
	fi.Mutex.Lock()
	defer fi.Mutex.Unlock()

	if _, exists := fi.FeatureSet[featureName]; !exists {
		return fmt.Errorf("feature %s not enabled", featureName)
	}

	delete(fi.FeatureSet, featureName)
	fi.logFeatureActivity("disable", featureName)
	return nil
}

// IsFeatureEnabled checks if a feature is enabled in the blockchain network
func (fi *FeatureIntegration) IsFeatureEnabled(featureName string) bool {
	fi.Mutex.Lock()
	defer fi.Mutex.Unlock()

	enabled, exists := fi.FeatureSet[featureName]
	return exists && enabled
}

// logFeatureActivity logs the activity related to feature management
func (fi *FeatureIntegration) logFeatureActivity(action, featureName string) {
	logEntry := map[string]interface{}{
		"action":    action,
		"feature":   featureName,
		"timestamp": time.Now(),
	}

	// In a real-world scenario, this would be logged to a file, database, or monitoring system
	fmt.Printf("Feature Log: %v\n", logEntry)
}

// EncryptData encrypts data using AES
func (fi *FeatureIntegration) EncryptData(data map[string]interface{}) (string, error) {
	fi.Mutex.Lock()
	defer fi.Mutex.Unlock()

	hashedKey := sha256.Sum256([]byte(fi.SecretKey))
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return "", err
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(dataBytes))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], dataBytes)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts data using AES
func (fi *FeatureIntegration) DecryptData(encryptedData string) (map[string]interface{}, error) {
	fi.Mutex.Lock()
	defer fi.Mutex.Unlock()

	hashedKey := sha256.Sum256([]byte(fi.SecretKey))
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return nil, err
	}

	ciphertext, err := base64.URLEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	var data map[string]interface{}
	if err := json.Unmarshal(ciphertext, &data); err != nil {
		return nil, err
	}

	return data, nil
}

// HandleFeatureRequest handles requests for enabling or disabling features
func (fi *FeatureIntegration) HandleFeatureRequest(request map[string]interface{}) (map[string]interface{}, error) {
	action, ok := request["action"].(string)
	if !ok {
		return nil, errors.New("invalid request: missing action")
	}

	featureName, ok := request["featureName"].(string)
	if !ok {
		return nil, errors.New("invalid request: missing featureName")
	}

	var response map[string]interface{}
	var err error

	switch action {
	case "enable":
		err = fi.EnableFeature(featureName)
		response = map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("feature %s enabled", featureName),
		}
	case "disable":
		err = fi.DisableFeature(featureName)
		response = map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("feature %s disabled", featureName),
		}
	default:
		err = errors.New("invalid action")
		response = map[string]interface{}{
			"status":  "error",
			"message": "invalid action",
		}
	}

	if err != nil {
		return map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		}, err
	}

	return response, nil
}

// AddAdditionalSecurityHeaders adds additional security headers to the API request
func (fi *FeatureIntegration) AddAdditionalSecurityHeaders(req *http.Request) {
	req.Header.Set("X-Request-ID", generateRequestID())
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))
}

// generateRequestID generates a unique request ID for tracking purposes
func generateRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
