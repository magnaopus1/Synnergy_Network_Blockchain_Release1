package core


import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"crypto/sha256"
	"golang.org/x/crypto/scrypt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"
)

// AIRequest represents a request to the AI assistant.
type AIRequest struct {
	UserID    string `json:"user_id"`
	Timestamp int64  `json:"timestamp"`
	Message   string `json:"message"`
}

// AIResponse represents a response from the AI assistant.
type AIResponse struct {
	UserID    string `json:"user_id"`
	Timestamp int64  `json:"timestamp"`
	Response  string `json:"response"`
}

// EncryptData encrypts data using AES with the given key and returns the encrypted data.
func EncryptData(data []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, ciphertext...), nil
}

// DecryptData decrypts data using AES with the given key and returns the decrypted data.
func DecryptData(data []byte, passphrase string) ([]byte, error) {
	salt := data[:8]
	data = data[8:]

	key, err := scrypt.Key([]byte(passphrase), salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GenerateHash generates a SHA256 hash for the given data.
func GenerateHash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// ProcessRequest processes an AI request and returns an AI response.
func ProcessRequest(req AIRequest) (AIResponse, error) {
	if req.Message == "" {
		return AIResponse{}, errors.New("message cannot be empty")
	}

	responseMessage := generateAIResponse(req.Message)
	resp := AIResponse{
		UserID:    req.UserID,
		Timestamp: time.Now().Unix(),
		Response:  responseMessage,
	}
	return resp, nil
}

// generateAIResponse generates a mock AI response for the given message.
func generateAIResponse(message string) string {
	// Implement your AI logic here. For the sake of example, we return a simple response.
	return "This is a response to your message: " + message
}

// LogRequest logs the AI request.
func LogRequest(req AIRequest) {
	data, err := json.Marshal(req)
	if err != nil {
		log.Printf("Error logging request: %v", err)
		return
	}
	log.Printf("AI Request: %s", string(data))
}

// LogResponse logs the AI response.
func LogResponse(resp AIResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		log.Printf("Error logging response: %v", err)
		return
	}
	log.Printf("AI Response: %s", string(data))
}

// SaveEncryptedLog saves the encrypted AI request and response log.
func SaveEncryptedLog(req AIRequest, resp AIResponse, passphrase string) error {
	logData := struct {
		Request  AIRequest  `json:"request"`
		Response AIResponse `json:"response"`
	}{
		Request:  req,
		Response: resp,
	}

	data, err := json.Marshal(logData)
	if err != nil {
		return err
	}

	encryptedData, err := EncryptData(data, passphrase)
	if err != nil {
		return err
	}

	// Save encryptedData to your storage (e.g., file, database)
	// For the sake of example, we'll just log it
	log.Printf("Encrypted Log: %x", encryptedData)
	return nil
}

// RetrieveDecryptedLog retrieves and decrypts the AI log.
func RetrieveDecryptedLog(encryptedData []byte, passphrase string) (AIRequest, AIResponse, error) {
	data, err := DecryptData(encryptedData, passphrase)
	if err != nil {
		return AIRequest{}, AIResponse{}, err
	}

	var logData struct {
		Request  AIRequest  `json:"request"`
		Response AIResponse `json:"response"`
	}
	if err := json.Unmarshal(data, &logData); err != nil {
		return AIRequest{}, AIResponse{}, err
	}

	return logData.Request, logData.Response, nil
}
