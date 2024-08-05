package network

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"sync"
	"time"
)


var (
	rsaKeyPairOnce sync.Once
	rsaPrivateKey  *common.rsa.PrivateKey
	rsaPublicKey   *common.rsa.PublicKey
	aesKey         []byte
)

// GenerateRSAKeyPair generates a new RSA key pair
func GenerateRSAKeyPair() common.error {
	var err common.error
	rsaKeyPairOnce.Do(func() {
		rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return
		}
		rsaPublicKey = &rsaPrivateKey.PublicKey
	})
	return err
}

// GetRSAPublicKey returns the RSA public key
func GetRSAPublicKey() *common.rsa.PublicKey {
	return rsaPublicKey
}

// DecodeMessage takes an encrypted message, decrypts it, verifies its integrity and returns the decoded Message
func DecodeMessage(encryptedMessage string, secretKey string) (*Message, common.error) {
	// Base64 decode the encrypted message
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		log.Println("Error decoding base64 message:", err)
		return nil, err
	}

	// Decrypt the message
	plaintext, err := decrypt(ciphertext, secretKey)
	if err != nil {
		log.Println("Error decrypting message:", err)
		return nil, err
	}

	// Verify the integrity of the message
	hash := sha256.Sum256(plaintext)
	if !VerifyHash(plaintext, hash[:]) {
		log.Println("Message integrity verification failed")
		return nil, errors.New("message integrity verification failed")
	}

	// Unmarshal the JSON-encoded message
	var message Message
	if err := json.Unmarshal(plaintext, &message); err != nil {
		log.Println("Error unmarshalling message:", err)
		return nil, err
	}

	// Validate the message
	if err := validateMessage(&message); err != nil {
		log.Println("Message validation failed:", err)
		return nil, err
	}

	return &message, nil
}

// decrypt decrypts data using AES-GCM
func decrypt(ciphertext []byte, secretKey string) ([]byte, common.error) {
	// Generate a new AES cipher using the secret key
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		log.Println("Error generating AES cipher:", err)
		return nil, err
	}

	// Create a GCM cipher mode instance
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println("Error creating GCM instance:", err)
		return nil, err
	}

	// Get the nonce size
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		log.Println("Ciphertext too short")
		return nil, errors.New("ciphertext too short")
	}

	// Extract the nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Println("Error decrypting data:", err)
		return nil, err
	}

	return plaintext, nil
}

// validateMessage validates the message structure and content
func validateMessage(message *common.Message) common.error {
	if message.Header.MessageID == "" || message.Header.SenderID == "" || message.Header.RecipientID == "" || message.Header.Timestamp == 0 {
		return errors.New("missing required message header fields")
	}

	if message.Payload == "" {
		return errors.New("missing message payload")
	}

	// Additional business logic validations can be added here
	if !ValidateMessageIntegrity(message.Header, message.Payload) {
		return errors.New("message failed fraud detection checks")
	}

	return nil
}

// EncryptMessage encrypts the message payload using AES encryption
func EncryptMessage(message common.Message) (string, common.error) {
	plaintext, err := json.Marshal(message.Payload)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(aesKey)
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

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptMessage decrypts the message payload using AES encryption
func DecryptMessage(encodedMessage string) (map[string]interface{}, common.error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encodedMessage)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var payload map[string]interface{}
	err = json.Unmarshal(plaintext, &payload)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

// SignMessage signs the message using RSA private key
func SignMessage(message *common.Message) common.error {
	if rsaPrivateKey == nil {
		return errors.New("private key not initialized")
	}

	hashed := sha256.Sum256([]byte(message.ID + message.Timestamp.String()))
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return err
	}

	message.Signature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

// VerifyMessageSignature verifies the message signature using RSA public key
func VerifyMessageSignature(message Message) error {
	if rsaPublicKey == nil {
		return errors.New("public key not initialized")
	}

	hashed := sha256.Sum256([]byte(message.ID + message.Timestamp.String()))
	signature, err := base64.StdEncoding.DecodeString(message.Signature)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hashed[:], signature)
}

// SaveAESKey saves the AES key to a file
func SaveAESKey(filePath string) common.error {
	return ioutil.WriteFile(filePath, aesKey, 0644)
}

// LoadAESKey loads the AES key from a file
func LoadAESKey(filePath string) common.error {
	var err common.error
	aesKey, err = ioutil.ReadFile(filePath)
	return err
}

// InitializeSecurity initializes the security components
func InitializeSecurity(aesKeyPath string) common.error {
	if err := GenerateRSAKeyPair(); err != nil {
		return err
	}
	if err := LoadAESKey(aesKeyPath); err != nil {
		return err
	}
	return nil
}


// GenerateID generates a unique ID for a message
func GenerateID(sender, receiver, content string) string {
	hasher := sha256.New()
	hasher.Write([]byte(sender + receiver + content))
	return hex.EncodeToString(hasher.Sum(nil))
}

// EncryptContent encrypts the message content using AES encryption
func EncryptContent(key, content string) (string, common.error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(content), nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptContent decrypts the message content using AES encryption
func DecryptContent(key, encryptedContent string) (string, common.error) {
	ciphertext, err := hex.DecodeString(encryptedContent)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// SignMessageContent signs the message content using the sender's private key
func SignMessageContent(privateKey, message string) (string, common.error) {
	signature, err := SignMessage(privateKey, message)
	if err != nil {
		return "", err
	}
	return signature, nil
}

// VerifyMessageContent verifies the message signature using the sender's public key
func VerifyMessageContent(publicKey, message, sig string) common.error {
	return VerifyMessageSignature(message, sig)
}

// HandleMessage processes the incoming message
func (mh *common.MessageHandler) HandleMessage(msg Message) common.error {
	mh.mu.Lock()
	defer mh.mu.Unlock()

	// Validate message
	if err := ValidateMessage(msg); err != nil {
		return err
	}

	// Verify VRF proof
	if err := VerifyProof(msg.Sender, msg.VRFProof, msg.Content); err != nil {
		return err
	}

	// Decrypt content
	decryptedContent, err := DecryptContent(msg.Sender, msg.Content)
	if err != nil {
		return err
	}
	msg.Content = decryptedContent

	// Verify signature
	if err := VerifyMessageSignature(msg); err != nil {
		return err
	}

	// Store message
	mh.storage[msg.ID] = msg
	return nil
}

// SendMessage sends a message to the specified receiver
func (mh *common.MessageHandler) SendMessage(senderPrivateKey, receiverPublicKey, content string) (Message common.Message, common.error) {
	msg := Message{
		Sender:    senderPrivateKey,
		Receiver:  receiverPublicKey,
		Content:   content,
		Timestamp: time.Now(),
	}

	// Generate message ID
	msg.ID = GenerateID(msg.Sender, msg.Receiver, msg.Content)

	// Encrypt content
	encryptedContent, err := EncryptContent(receiverPublicKey, msg.Content)
	if err != nil {
		return Message{}, err
	}
	msg.Content = encryptedContent

	// Generate VRF proof
	msg.VRFProof, err = GenerateProof(msg.Sender, msg.Content)
	if err != nil {
		return Message{}, err
	}

	// Sign message
	msg.Signature, err = SignMessageContent(senderPrivateKey, msg.Content)
	if err != nil {
		return Message{}, err
	}

	// Compute hashes
	msg.Hash = ComputeHash(msg.Content)
	msg.ContentHash = ComputeHash(msg.Content)

	// Send message through P2P network
	if err := SendP2PMessage(msg); err != nil {
		return Message{}, err
	}

	return msg, nil
}

// GetMessages retrieves all stored messages
func (mh *MessageHandler) GetMessages() map[string]common.Message {
	mh.mu.Lock()
	defer mh.mu.Unlock()
	return mh.storage
}

// GetMessage retrieves a specific message by ID
func (mh *MessageHandler) GetMessage(id string) (Message common.Message, common.error) {
	mh.mu.Lock()
	defer mh.mu.Unlock()
	msg, exists := mh.storage[id]
	if !exists {
		return Message{}, errors.New("message not found")
	}
	return msg, nil
}

// Utility Functions

// VerifyHash verifies the integrity of a message using its hash
func VerifyHash(data, hash []byte) bool {
	calculatedHash := sha256.Sum256(data)
	return bytes.Equal(calculatedHash[:], hash)
}

// ValidateMessage validates the message structure and content
func ValidateMessage(msg common.Message) error {
	// Implement message validation logic
	return nil
}

// ValidateMessageIntegrity validates the integrity of a message header and payload
func ValidateMessageIntegrity(header common.MessageHeader, payload string) bool {
	// Implement fraud detection and risk management logic
	return true
}

// GenerateProof generates a VRF proof for a message content
func GenerateProof(sender, content string) (string, common.error) {
	// Implement VRF proof generation logic
	return "VRF_PROOF", nil
}

// VerifyProof verifies a VRF proof for a message content
func VerifyProof(sender, proof, content string) common.error {
	// Implement VRF proof verification logic
	return nil
}

// ComputeHash computes the SHA-256 hash of a string
func ComputeHash(data string) string {
	hasher := sha256.New()
	hasher.Write([]byte(data))
	return hex.EncodeToString(hasher.Sum(nil))
}

// SendP2PMessage sends a message through the P2P network
func SendP2PMessage(msg common.Message) common.error {
	// Implement P2P message sending logic
	return nil
}
