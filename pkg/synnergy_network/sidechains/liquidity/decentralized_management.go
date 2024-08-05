package liquidity

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
)

// Node represents a node in the decentralized management system
type Node struct {
	ID       string
	PublicKey  string
	PrivateKey string
	Endpoint   string
}

// DecentralizedManagement handles decentralized governance and operations
type DecentralizedManagement struct {
	nodes map[string]Node
	mu    sync.RWMutex
}

// NewDecentralizedManagement creates a new DecentralizedManagement instance
func NewDecentralizedManagement() *DecentralizedManagement {
	return &DecentralizedManagement{
		nodes: make(map[string]Node),
	}
}

// AddNode adds a new node to the management system
func (dm *DecentralizedManagement) AddNode(id, publicKey, privateKey, endpoint string) error {
	if id == "" || publicKey == "" || privateKey == "" || endpoint == "" {
		return errors.New("invalid node data")
	}

	dm.mu.Lock()
	defer dm.mu.Unlock()

	dm.nodes[id] = Node{
		ID:         id,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Endpoint:   endpoint,
	}
	return nil
}

// RemoveNode removes a node from the management system
func (dm *DecentralizedManagement) RemoveNode(id string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if _, exists := dm.nodes[id]; !exists {
		return errors.New("node not found")
	}

	delete(dm.nodes, id)
	return nil
}

// ListNodes lists all nodes in the management system
func (dm *DecentralizedManagement) ListNodes() []Node {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	nodes := make([]Node, 0, len(dm.nodes))
	for _, node := range dm.nodes {
		nodes = append(nodes, node)
	}
	return nodes
}

// EncryptData encrypts data using AES encryption with a given key
func (dm *DecentralizedManagement) EncryptData(key, plaintext string) (string, error) {
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

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptData decrypts data using AES encryption with a given key
func (dm *DecentralizedManagement) DecryptData(key, ciphertext string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	data, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// HashData generates a SHA-256 hash of the given data
func (dm *DecentralizedManagement) HashData(data string) string {
	hash := sha256.New()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

// VerifyNode verifies the existence of a node in the management system
func (dm *DecentralizedManagement) VerifyNode(id string) (bool, error) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	if _, exists := dm.nodes[id]; !exists {
		return false, errors.New("node not found")
	}

	return true, nil
}

// ConsensusProtocol simulates a consensus protocol among nodes
func (dm *DecentralizedManagement) ConsensusProtocol(data string) (string, error) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	// Simulate consensus algorithm (replace with actual implementation)
	fmt.Println("Running consensus protocol on data:", data)

	consensusResult := "consensus_reached" // Placeholder for actual consensus result
	return consensusResult, nil
}

// SecureMessage securely sends a message to a specific node
func (dm *DecentralizedManagement) SecureMessage(nodeID, message, key string) (string, error) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	node, exists := dm.nodes[nodeID]
	if !exists {
		return "", errors.New("node not found")
	}

	encryptedMessage, err := dm.EncryptData(key, message)
	if err != nil {
		return "", err
	}

	// Simulate message sending (replace with actual implementation)
	fmt.Printf("Sending encrypted message to node %s at %s: %s\n", node.ID, node.Endpoint, encryptedMessage)

	return encryptedMessage, nil
}

// ReceiveSecureMessage securely receives a message from a specific node
func (dm *DecentralizedManagement) ReceiveSecureMessage(nodeID, encryptedMessage, key string) (string, error) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	node, exists := dm.nodes[nodeID]
	if !exists {
		return "", errors.New("node not found")
	}

	// Simulate message receiving (replace with actual implementation)
	fmt.Printf("Receiving encrypted message from node %s at %s: %s\n", node.ID, node.Endpoint, encryptedMessage)

	decryptedMessage, err := dm.DecryptData(key, encryptedMessage)
	if err != nil {
		return "", err
	}

	return decryptedMessage, nil
}
