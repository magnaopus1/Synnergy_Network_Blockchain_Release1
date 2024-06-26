package mobile_node

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/argon2"
)

// MobileNode represents a mobile node in the Synnergy Network
type MobileNode struct {
	mu               sync.Mutex
	dataStorage      map[string][]byte
	encryptionKey    []byte
	blockchainData   []byte
	lastSyncTime     time.Time
	authenticated    bool
	userCredentials  map[string]string
}

// NewMobileNode initializes a new MobileNode with default settings
func NewMobileNode() *MobileNode {
	return &MobileNode{
		dataStorage:     make(map[string][]byte),
		encryptionKey:   nil,
		blockchainData:  nil,
		lastSyncTime:    time.Time{},
		authenticated:   false,
		userCredentials: make(map[string]string),
	}
}

// GenerateEncryptionKey generates a new AES encryption key using Argon2 for secure key derivation
func (node *MobileNode) GenerateEncryptionKey(password, salt []byte) ([]byte, error) {
	node.mu.Lock()
	defer node.mu.Unlock()
	key := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
	node.encryptionKey = key
	return key, nil
}

// EncryptData encrypts data using AES-GCM
func (node *MobileNode) EncryptData(plaintext []byte) ([]byte, error) {
	node.mu.Lock()
	defer node.mu.Unlock()
	if node.encryptionKey == nil {
		return nil, errors.New("encryption key is not set")
	}

	block, err := aes.NewCipher(node.encryptionKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptData decrypts data using AES-GCM
func (node *MobileNode) DecryptData(ciphertext []byte) ([]byte, error) {
	node.mu.Lock()
	defer node.mu.Unlock()
	if node.encryptionKey == nil {
		return nil, errors.New("encryption key is not set")
	}

	block, err := aes.NewCipher(node.encryptionKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// SyncBlockchainData syncs blockchain data incrementally
func (node *MobileNode) SyncBlockchainData(newData []byte) {
	node.mu.Lock()
	defer node.mu.Unlock()
	node.blockchainData = append(node.blockchainData, newData...)
	node.lastSyncTime = time.Now()
}

// AuthenticateUser authenticates a user with given credentials
func (node *MobileNode) AuthenticateUser(username, password string) bool {
	node.mu.Lock()
	defer node.mu.Unlock()
	storedPassword, exists := node.userCredentials[username]
	if !exists {
		return false
	}

	hashedPassword := sha256.Sum256([]byte(password))
	if storedPassword == string(hashedPassword[:]) {
		node.authenticated = true
		return true
	}
	return false
}

// RegisterUser registers a new user with credentials
func (node *MobileNode) RegisterUser(username, password string) {
	node.mu.Lock()
	defer node.mu.Unlock()
	hashedPassword := sha256.Sum256([]byte(password))
	node.userCredentials[username] = string(hashedPassword[:])
}

// SignTransaction signs a transaction using RSA
func (node *MobileNode) SignTransaction(privateKey *rsa.PrivateKey, transaction []byte) ([]byte, error) {
	node.mu.Lock()
	defer node.mu.Unlock()
	hashed := sha256.Sum256(transaction)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// VerifyTransaction verifies a transaction signature using RSA
func (node *MobileNode) VerifyTransaction(publicKey *rsa.PublicKey, transaction, signature []byte) error {
	node.mu.Lock()
	defer node.mu.Unlock()
	hashed := sha256.Sum256(transaction)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
}

// LoadPrivateKey loads an RSA private key from PEM-encoded data
func LoadPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// LoadPublicKey loads an RSA public key from PEM-encoded data
func LoadPublicKey(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	return x509.ParsePKCS1PublicKey(block.Bytes)
}

// HealthCheck performs a health check on the mobile node
func (node *MobileNode) HealthCheck() error {
	node.mu.Lock()
	defer node.mu.Unlock()
	// Check encryption key presence
	if node.encryptionKey == nil {
		return errors.New("encryption key is not set")
	}

	// Check if blockchain data is present
	if len(node.blockchainData) == 0 {
		return errors.New("no blockchain data available")
	}

	// Check if the node is authenticated
	if !node.authenticated {
		return errors.New("node is not authenticated")
	}

	log.Println("Mobile node health check passed")
	return nil
}
