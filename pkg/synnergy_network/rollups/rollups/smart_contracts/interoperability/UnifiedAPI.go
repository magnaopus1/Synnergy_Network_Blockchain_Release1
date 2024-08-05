package interoperability

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// UnifiedAPI provides a unified interface for interacting with different layers of the blockchain
type UnifiedAPI struct {
	BaseURL   string
	APIKey    string
	SecretKey string
	Mutex     sync.Mutex
}

// NewUnifiedAPI creates a new instance of UnifiedAPI
func NewUnifiedAPI(baseURL, apiKey, secretKey string) *UnifiedAPI {
	return &UnifiedAPI{
		BaseURL:   baseURL,
		APIKey:    apiKey,
		SecretKey: secretKey,
	}
}

// sendRequest sends an HTTP request to the specified endpoint with the provided payload and returns the response
func (api *UnifiedAPI) sendRequest(endpoint string, payload map[string]interface{}) (map[string]interface{}, error) {
	api.Mutex.Lock()
	defer api.Mutex.Unlock()

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/%s", api.BaseURL, endpoint), bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("API-Key", api.APIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	return response, nil
}

// EncryptData encrypts data using AES
func (api *UnifiedAPI) EncryptData(data map[string]interface{}) (string, error) {
	api.Mutex.Lock()
	defer api.Mutex.Unlock()

	hashedKey := sha256.Sum256([]byte(api.SecretKey))
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
func (api *UnifiedAPI) DecryptData(encryptedData string) (map[string]interface{}, error) {
	api.Mutex.Lock()
	defer api.Mutex.Unlock()

	hashedKey := sha256.Sum256([]byte(api.SecretKey))
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

// PerformCrossLayerCall performs a cross-layer call to the specified endpoint with the provided payload
func (api *UnifiedAPI) PerformCrossLayerCall(endpoint string, payload map[string]interface{}) (map[string]interface{}, error) {
	encryptedPayload, err := api.EncryptData(payload)
	if err != nil {
		return nil, err
	}

	response, err := api.sendRequest(endpoint, map[string]interface{}{"data": encryptedPayload})
	if err != nil {
		return nil, err
	}

	decryptedResponse, err := api.DecryptData(response["data"].(string))
	if err != nil {
		return nil, err
	}

	return decryptedResponse, nil
}

// LogAPIActivity logs the details of the API activity
func (api *UnifiedAPI) LogAPIActivity(activity string, details map[string]interface{}) {
	api.Mutex.Lock()
	defer api.Mutex.Unlock()

	logEntry := map[string]interface{}{
		"activity": activity,
		"details":  details,
		"timestamp": time.Now(),
	}

	// In a real-world scenario, this would be logged to a file, database, or monitoring system
	fmt.Printf("API Log: %v\n", logEntry)
}

// AddAdditionalSecurityHeaders adds additional security headers to the API request
func (api *UnifiedAPI) AddAdditionalSecurityHeaders(req *http.Request) {
	req.Header.Set("X-Request-ID", generateRequestID())
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))
}

// generateRequestID generates a unique request ID for tracking purposes
func generateRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
