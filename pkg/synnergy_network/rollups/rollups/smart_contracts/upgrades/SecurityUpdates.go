package upgrades

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// SecurityUpdates handles the implementation and management of security updates for smart contracts in the blockchain network.
type SecurityUpdates struct {
	Updates     map[string]Update
	APIKey      string
	SecretKey   string
	UpdateMutex sync.Mutex
}

// Update represents a security update applied to a smart contract.
type Update struct {
	ContractName string
	Version      string
	Details      string
	AppliedAt    time.Time
}

// NewSecurityUpdates creates a new instance of SecurityUpdates.
func NewSecurityUpdates(apiKey, secretKey string) *SecurityUpdates {
	return &SecurityUpdates{
		Updates:   make(map[string]Update),
		APIKey:    apiKey,
		SecretKey: secretKey,
	}
}

// ApplyUpdate applies a security update to a smart contract.
func (su *SecurityUpdates) ApplyUpdate(contractName, version, details string) error {
	su.UpdateMutex.Lock()
	defer su.UpdateMutex.Unlock()

	updateKey := fmt.Sprintf("%s:%s", contractName, version)
	if _, exists := su.Updates[updateKey]; exists {
		return fmt.Errorf("update %s for contract %s already applied", version, contractName)
	}

	su.Updates[updateKey] = Update{
		ContractName: contractName,
		Version:      version,
		Details:      details,
		AppliedAt:    time.Now(),
	}

	su.logUpdateActivity("apply", contractName, version)
	return nil
}

// RevokeUpdate revokes a security update from a smart contract.
func (su *SecurityUpdates) RevokeUpdate(contractName, version string) error {
	su.UpdateMutex.Lock()
	defer su.UpdateMutex.Unlock()

	updateKey := fmt.Sprintf("%s:%s", contractName, version)
	if _, exists := su.Updates[updateKey]; !exists {
		return fmt.Errorf("update %s for contract %s does not exist", version, contractName)
	}

	delete(su.Updates, updateKey)
	su.logUpdateActivity("revoke", contractName, version)
	return nil
}

// IsUpdateApplied checks if a security update is applied to a smart contract.
func (su *SecurityUpdates) IsUpdateApplied(contractName, version string) bool {
	su.UpdateMutex.Lock()
	defer su.UpdateMutex.Unlock()

	updateKey := fmt.Sprintf("%s:%s", contractName, version)
	_, exists := su.Updates[updateKey]
	return exists
}

// logUpdateActivity logs the activity related to security updates.
func (su *SecurityUpdates) logUpdateActivity(action, contractName, version string) {
	logEntry := map[string]interface{}{
		"action":      action,
		"contract":    contractName,
		"version":     version,
		"timestamp":   time.Now(),
	}

	// In a real-world scenario, this would be logged to a file, database, or monitoring system
	fmt.Printf("Security Update Log: %v\n", logEntry)
}

// EncryptUpdateData encrypts update details using AES.
func (su *SecurityUpdates) EncryptUpdateData(data map[string]interface{}) (string, error) {
	su.UpdateMutex.Lock()
	defer su.UpdateMutex.Unlock()

	hashedKey := sha256.Sum256([]byte(su.SecretKey))
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

// DecryptUpdateData decrypts update details using AES.
func (su *SecurityUpdates) DecryptUpdateData(encryptedData string) (map[string]interface{}, error) {
	su.UpdateMutex.Lock()
	defer su.UpdateMutex.Unlock()

	hashedKey := sha256.Sum256([]byte(su.SecretKey))
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

// HandleUpdateRequest handles requests for applying or revoking security updates.
func (su *SecurityUpdates) HandleUpdateRequest(request map[string]interface{}) (map[string]interface{}, error) {
	action, ok := request["action"].(string)
	if !ok {
		return nil, errors.New("invalid request: missing action")
	}

	contractName, ok := request["contractName"].(string)
	if !ok {
		return nil, errors.New("invalid request: missing contractName")
	}

	version, ok := request["version"].(string)
	if !ok {
		return nil, errors.New("invalid request: missing version")
	}

	var response map[string]interface{}
	var err error

	switch action {
	case "apply":
		details, ok := request["details"].(string)
		if !ok {
			return nil, errors.New("invalid request: missing details for apply action")
		}
		err = su.ApplyUpdate(contractName, version, details)
		response = map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("update %s applied to contract %s", version, contractName),
		}
	case "revoke":
		err = su.RevokeUpdate(contractName, version)
		response = map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("update %s revoked from contract %s", version, contractName),
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

// AddAdditionalSecurityHeaders adds additional security headers to the API request.
func (su *SecurityUpdates) AddAdditionalSecurityHeaders(req *http.Request) {
	req.Header.Set("X-Request-ID", generateRequestID())
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))
}

// generateRequestID generates a unique request ID for tracking purposes.
func generateRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
