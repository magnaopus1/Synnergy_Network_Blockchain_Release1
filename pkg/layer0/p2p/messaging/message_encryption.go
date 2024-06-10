package messaging

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"sync"

	"golang.org/x/crypto/scrypt"
)

// Encryptor defines methods for message encryption and decryption
type Encryptor struct {
	key []byte
}

// NewEncryptor creates a new Encryptor instance
func NewEncryptor(passphrase string) (*Encryptor, error) {
	key, err := scrypt.Key([]byte(passphrase), []byte("somesalt"), 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}

	return &Encryptor{key: key}, nil
}

// Encrypt encrypts the given plaintext using AES
func (e *Encryptor) Encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given ciphertext using AES
func (e *Encryptor) Decrypt(ciphertext string) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("invalid ciphertext")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// MessageHandler handles the message encryption and decryption logic
type MessageHandler struct {
	encryptor *Encryptor
}

// NewMessageHandler creates a new MessageHandler instance
func NewMessageHandler(passphrase string) (*MessageHandler, error) {
	encryptor, err := NewEncryptor(passphrase)
	if err != nil {
		return nil, err
	}

	return &MessageHandler{encryptor: encryptor}, nil
}

// HandleMessageEncryption encrypts the message and returns the encrypted message
func (mh *MessageHandler) HandleMessageEncryption(message []byte) (string, error) {
	return mh.encryptor.Encrypt(message)
}

// HandleMessageDecryption decrypts the message and returns the decrypted message
func (mh *MessageHandler) HandleMessageDecryption(encryptedMessage string) ([]byte, error) {
	return mh.encryptor.Decrypt(encryptedMessage)
}

// Example usage
func main() {
	passphrase := "securepassphrase"

	messageHandler, err := NewMessageHandler(passphrase)
	if err != nil {
		log.Fatalf("failed to create message handler: %v", err)
	}

	message := "Hello, secure world!"
	encryptedMessage, err := messageHandler.HandleMessageEncryption([]byte(message))
	if err != nil {
		log.Fatalf("failed to encrypt message: %v", err)
	}

	fmt.Printf("Encrypted Message: %s\n", encryptedMessage)

	decryptedMessage, err := messageHandler.HandleMessageDecryption(encryptedMessage)
	if err != nil {
		log.Fatalf("failed to decrypt message: %v", err)
	}

	fmt.Printf("Decrypted Message: %s\n", string(decryptedMessage))
}
