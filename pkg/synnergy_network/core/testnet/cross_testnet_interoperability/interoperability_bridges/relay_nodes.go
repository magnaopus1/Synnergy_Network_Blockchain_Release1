package interoperability_bridges

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// RelayNode represents a relay node in the cross-chain interoperability system
type RelayNode struct {
	NodeID          string    // Unique identifier for the relay node
	ChainA          string    // The first blockchain
	ChainB          string    // The second blockchain
	Status          string    // Status of the relay node
	LastActive      time.Time // Last active timestamp
	EncryptionKey   []byte    // Encryption key for secure communication
}

// RelayNodeManager manages relay nodes
type RelayNodeManager struct {
	nodes map[string]*RelayNode
	mu    sync.Mutex
}

// NewRelayNodeManager creates a new RelayNodeManager
func NewRelayNodeManager() *RelayNodeManager {
	return &RelayNodeManager{
		nodes: make(map[string]*RelayNode),
	}
}

// AddRelayNode adds a new relay node
func (rnm *RelayNodeManager) AddRelayNode(chainA, chainB string) (string, error) {
	rnm.mu.Lock()
	defer rnm.mu.Unlock()

	nodeID := generateNodeID(chainA, chainB)
	if _, exists := rnm.nodes[nodeID]; exists {
		return "", errors.New("relay node already exists")
	}

	key, err := generateEncryptionKey()
	if err != nil {
		return "", err
	}

	node := &RelayNode{
		NodeID:        nodeID,
		ChainA:        chainA,
		ChainB:        chainB,
		Status:        "active",
		LastActive:    time.Now(),
		EncryptionKey: key,
	}

	rnm.nodes[nodeID] = node

	return nodeID, nil
}

// GetRelayNode retrieves a relay node by its ID
func (rnm *RelayNodeManager) GetRelayNode(nodeID string) (*RelayNode, error) {
	rnm.mu.Lock()
	defer rnm.mu.Unlock()

	node, exists := rnm.nodes[nodeID]
	if !exists {
		return nil, errors.New("relay node not found")
	}

	return node, nil
}

// UpdateRelayNodeStatus updates the status of a relay node
func (rnm *RelayNodeManager) UpdateRelayNodeStatus(nodeID, status string) error {
	rnm.mu.Lock()
	defer rnm.mu.Unlock()

	node, exists := rnm.nodes[nodeID]
	if !exists {
		return errors.New("relay node not found")
	}

	node.Status = status
	node.LastActive = time.Now()

	return nil
}

// RemoveRelayNode removes a relay node
func (rnm *RelayNodeManager) RemoveRelayNode(nodeID string) error {
	rnm.mu.Lock()
	defer rnm.mu.Unlock()

	if _, exists := rnm.nodes[nodeID]; !exists {
		return errors.New("relay node not found")
	}

	delete(rnm.nodes, nodeID)

	return nil
}

// generateNodeID generates a unique node ID
func generateNodeID(chainA, chainB string) string {
	data := chainA + chainB + time.Now().String()
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// generateEncryptionKey generates a secure encryption key using scrypt
func generateEncryptionKey() ([]byte, error) {
	passphrase := make([]byte, 32)
	if _, err := rand.Read(passphrase); err != nil {
		return nil, err
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key, err := scrypt.Key(passphrase, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// EncryptData encrypts data using AES
func EncryptData(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// DecryptData decrypts AES encrypted data
func DecryptData(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

	return plaintext, nil
}

// TransmitData securely transmits data between chains using relay nodes
func (rn *RelayNode) TransmitData(data []byte) ([]byte, error) {
	encryptedData, err := EncryptData(data, rn.EncryptionKey)
	if err != nil {
		return nil, err
	}

	// Simulate data transmission and return encrypted data
	// In a real implementation, this would involve network communication
	return encryptedData, nil
}

// ReceiveData securely receives data between chains using relay nodes
func (rn *RelayNode) ReceiveData(encryptedData []byte) ([]byte, error) {
	plaintext, err := DecryptData(encryptedData, rn.EncryptionKey)
	if err != nil {
		return nil, err
	}

	// Simulate data reception
	// In a real implementation, this would involve network communication
	return plaintext, nil
}

// MonitorRelayNode monitors the status of a relay node
func MonitorRelayNode(rnm *RelayNodeManager, nodeID string) {
	for {
		time.Sleep(10 * time.Second)
		node, err := rnm.GetRelayNode(nodeID)
		if err != nil {
			fmt.Println(err)
			continue
		}

		if node.Status != "active" {
			fmt.Printf("Relay node %s is not active. Status: %s\n", nodeID, node.Status)
		} else {
			fmt.Printf("Relay node %s is active\n", nodeID)
		}
	}
}
