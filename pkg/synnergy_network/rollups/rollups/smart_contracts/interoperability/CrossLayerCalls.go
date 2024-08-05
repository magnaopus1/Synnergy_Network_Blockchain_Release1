package interoperability

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

// CrossLayerCall represents a call across different layers of the blockchain
type CrossLayerCall struct {
	ID            string
	SourceLayer   string
	DestinationLayer string
	Payload       map[string]interface{}
	Response      map[string]interface{}
	Status        string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	Mutex         sync.Mutex
}

// NewCrossLayerCall creates a new instance of CrossLayerCall
func NewCrossLayerCall(id, sourceLayer, destinationLayer string, payload map[string]interface{}) *CrossLayerCall {
	return &CrossLayerCall{
		ID:               id,
		SourceLayer:      sourceLayer,
		DestinationLayer: destinationLayer,
		Payload:          payload,
		Status:           "pending",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
}

// Execute sends the payload to the destination layer and updates the status and response
func (clc *CrossLayerCall) Execute() error {
	clc.Mutex.Lock()
	defer clc.Mutex.Unlock()

	// Simulate sending the payload and receiving a response
	// In a real-world scenario, this would involve network communication and consensus mechanisms
	clc.Response = make(map[string]interface{})
	for k, v := range clc.Payload {
		clc.Response[k] = v
	}
	clc.Status = "completed"
	clc.UpdatedAt = time.Now()

	return nil
}

// EncryptPayload encrypts the payload using AES
func (clc *CrossLayerCall) EncryptPayload(secret string) (string, error) {
	clc.Mutex.Lock()
	defer clc.Mutex.Unlock()

	hashedKey := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return "", err
	}

	payloadBytes, err := json.Marshal(clc.Payload)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(payloadBytes))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], payloadBytes)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// DecryptPayload decrypts the payload using AES
func (clc *CrossLayerCall) DecryptPayload(secret, encryptedPayload string) error {
	clc.Mutex.Lock()
	defer clc.Mutex.Unlock()

	hashedKey := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return err
	}

	ciphertext, err := base64.URLEncoding.DecodeString(encryptedPayload)
	if err != nil {
		return err
	}

	if len(ciphertext) < aes.BlockSize {
		return errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	if err := json.Unmarshal(ciphertext, &clc.Payload); err != nil {
		return err
	}

	return nil
}

// UpdateStatus updates the status of the cross-layer call
func (clc *CrossLayerCall) UpdateStatus(status string) {
	clc.Mutex.Lock()
	defer clc.Mutex.Unlock()

	clc.Status = status
	clc.UpdatedAt = time.Now()
}

// GetPayload returns the payload of the cross-layer call
func (clc *CrossLayerCall) GetPayload() map[string]interface{} {
	clc.Mutex.Lock()
	defer clc.Mutex.Unlock()

	return clc.Payload
}

// SetPayload sets the payload of the cross-layer call
func (clc *CrossLayerCall) SetPayload(payload map[string]interface{}) {
	clc.Mutex.Lock()
	defer clc.Mutex.Unlock()

	clc.Payload = payload
	clc.UpdatedAt = time.Now()
}

// GetResponse returns the response of the cross-layer call
func (clc *CrossLayerCall) GetResponse() map[string]interface{} {
	clc.Mutex.Lock()
	defer clc.Mutex.Unlock()

	return clc.Response
}

// SetResponse sets the response of the cross-layer call
func (clc *CrossLayerCall) SetResponse(response map[string]interface{}) {
	clc.Mutex.Lock()
	defer clc.Mutex.Unlock()

	clc.Response = response
	clc.UpdatedAt = time.Now()
}

// LogCall logs the details of the cross-layer call
func (clc *CrossLayerCall) LogCall() {
	clc.Mutex.Lock()
	defer clc.Mutex.Unlock()

	fmt.Printf("CrossLayerCall ID: %s\n", clc.ID)
	fmt.Printf("SourceLayer: %s\n", clc.SourceLayer)
	fmt.Printf("DestinationLayer: %s\n", clc.DestinationLayer)
	fmt.Printf("Payload: %v\n", clc.Payload)
	fmt.Printf("Response: %v\n", clc.Response)
	fmt.Printf("Status: %s\n", clc.Status)
	fmt.Printf("CreatedAt: %v\n", clc.CreatedAt)
	fmt.Printf("UpdatedAt: %v\n", clc.UpdatedAt)
}
