package networking

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// EdgeNode represents an edge computing node in the network
type EdgeNode struct {
	Address      string
	Capabilities map[string]bool
	LastActive   time.Time
}

// EdgeNetworkManager manages edge nodes and their interactions
type EdgeNetworkManager struct {
	mutex     sync.Mutex
	edgeNodes map[string]*EdgeNode
}

// NewEdgeNetworkManager creates a new edge network manager
func NewEdgeNetworkManager() *EdgeNetworkManager {
	return &EdgeNetworkManager{
		edgeNodes: make(map[string]*EdgeNode),
	}
}

// AddEdgeNode adds a new edge node to the network
func (enm *EdgeNetworkManager) AddEdgeNode(address string, capabilities map[string]bool) {
	enm.mutex.Lock()
	defer enm.mutex.Unlock()
	enm.edgeNodes[address] = &EdgeNode{
		Address:      address,
		Capabilities: capabilities,
		LastActive:   time.Now(),
	}
}

// RemoveEdgeNode removes an edge node from the network
func (enm *EdgeNetworkManager) RemoveEdgeNode(address string) {
	enm.mutex.Lock()
	defer enm.mutex.Unlock()
	delete(enm.edgeNodes, address)
}

// UpdateEdgeNodeActivity updates the last active time of an edge node
func (enm *EdgeNetworkManager) UpdateEdgeNodeActivity(address string) {
	enm.mutex.Lock()
	defer enm.mutex.Unlock()
	if node, exists := enm.edgeNodes[address]; exists {
		node.LastActive = time.Now()
	}
}

// FindBestEdgeNode finds the best edge node based on capabilities and proximity
func (enm *EdgeNetworkManager) FindBestEdgeNode(requiredCapabilities map[string]bool) (*EdgeNode, error) {
	enm.mutex.Lock()
	defer enm.mutex.Unlock()

	var bestNode *EdgeNode
	for _, node := range enm.edgeNodes {
		if enm.nodeHasCapabilities(node, requiredCapabilities) {
			if bestNode == nil || node.LastActive.After(bestNode.LastActive) {
				bestNode = node
			}
		}
	}

	if bestNode == nil {
		return nil, errors.New("no suitable edge node found")
	}

	return bestNode, nil
}

func (enm *EdgeNetworkManager) nodeHasCapabilities(node *EdgeNode, requiredCapabilities map[string]bool) bool {
	for capability := range requiredCapabilities {
		if !node.Capabilities[capability] {
			return false
		}
	}
	return true
}

// EncryptMessage encrypts a message using AES encryption
func EncryptMessage(key, message string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	plaintext := []byte(message)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// DecryptMessage decrypts a message using AES encryption
func DecryptMessage(key, encryptedMessage string) (string, error) {
	ciphertext, _ := base64.URLEncoding.DecodeString(encryptedMessage)

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

// DeriveKey derives a secure key using Scrypt
func DeriveKey(password, salt string) ([]byte, error) {
	return scrypt.Key([]byte(password), []byte(salt), 16384, 8, 1, 32)
}

// SendTaskToEdgeNode sends a task to the best edge node for processing
func (enm *EdgeNetworkManager) SendTaskToEdgeNode(task string, requiredCapabilities map[string]bool, key string) error {
	edgeNode, err := enm.FindBestEdgeNode(requiredCapabilities)
	if err != nil {
		return err
	}

	encryptedTask, err := EncryptMessage(key, task)
	if err != nil {
		return err
	}

	// Simulate sending the encrypted task to the edge node
	fmt.Printf("Sending task to edge node %s: %s\n", edgeNode.Address, encryptedTask)
	// In a real implementation, this would be an actual network call

	return nil
}

// ReceiveTaskResult simulates receiving the result of a task from an edge node
func (enm *EdgeNetworkManager) ReceiveTaskResult(edgeNodeAddress string, encryptedResult string, key string) (string, error) {
	decryptedResult, err := DecryptMessage(key, encryptedResult)
	if err != nil {
		return "", err
	}

	fmt.Printf("Received result from edge node %s: %s\n", edgeNodeAddress, decryptedResult)
	return decryptedResult, nil
}

// Example usage
func main() {
	// Create a new edge network manager
	enm := NewEdgeNetworkManager()

	// Add some edge nodes with capabilities
	enm.AddEdgeNode("192.168.1.100", map[string]bool{"compute": true, "storage": true})
	enm.AddEdgeNode("192.168.1.101", map[string]bool{"compute": true})
	enm.AddEdgeNode("192.168.1.102", map[string]bool{"storage": true})

	// Derive a key for encryption/decryption
	password := "securepassword"
	salt := "randomsalt"
	key, _ := DeriveKey(password, salt)

	// Send a task to the best edge node
	task := "process data"
	requiredCapabilities := map[string]bool{"compute": true}
	if err := enm.SendTaskToEdgeNode(task, requiredCapabilities, string(key)); err != nil {
		fmt.Println("Error sending task to edge node:", err)
	}

	// Simulate receiving a task result from an edge node
	encryptedResult, _ := EncryptMessage(string(key), "task result data")
	enm.ReceiveTaskResult("192.168.1.100", encryptedResult, string(key))
}
