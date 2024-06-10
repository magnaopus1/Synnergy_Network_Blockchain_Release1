package webrtc_integration

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/pions/webrtc/v3"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// Node represents a network node with WebRTC capabilities
type Node struct {
	ID          string
	Address     string
	Connection  *webrtc.PeerConnection
	DataChannel *webrtc.DataChannel
}

// WebRTCManager manages the WebRTC integration
type WebRTCManager struct {
	nodes         map[string]*Node
	mutex         sync.Mutex
	encryptKey    []byte
	bootstrapNodes []string
}

// NewWebRTCManager creates a new WebRTCManager
func NewWebRTCManager(encryptKey []byte, bootstrapNodes []string) *WebRTCManager {
	return &WebRTCManager{
		nodes:         make(map[string]*Node),
		encryptKey:    encryptKey,
		bootstrapNodes: bootstrapNodes,
	}
}

// AddNode adds a new node to the network
func (m *WebRTCManager) AddNode(address string) error {
	nodeID := generateNodeID(address)

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.nodes[nodeID]; exists {
		return errors.New("node already exists")
	}

	config := webrtc.Configuration{}
	peerConnection, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return err
	}

	dataChannel, err := peerConnection.CreateDataChannel("data", nil)
	if err != nil {
		return err
	}

	node := &Node{
		ID:          nodeID,
		Address:     address,
		Connection:  peerConnection,
		DataChannel: dataChannel,
	}

	m.nodes[nodeID] = node
	return nil
}

// RemoveNode removes a node from the network
func (m *WebRTCManager) RemoveNode(nodeID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if node, exists := m.nodes[nodeID]; exists {
		node.Connection.Close()
		delete(m.nodes, nodeID)
	}
}

// SendMessage sends an encrypted message to a node
func (m *WebRTCManager) SendMessage(nodeID string, message []byte) error {
	m.mutex.Lock()
	node, exists := m.nodes[nodeID]
	m.mutex.Unlock()

	if !exists {
		return errors.New("node not found")
	}

	encryptedMessage, err := encryptData(message, m.encryptKey)
	if err != nil {
		return err
	}

	err = node.DataChannel.Send(encryptedMessage)
	if err != nil {
		return err
	}

	return nil
}

// ReceiveMessage receives and decrypts a message from a node
func (m *WebRTCManager) ReceiveMessage(nodeID string) ([]byte, error) {
	m.mutex.Lock()
	node, exists := m.nodes[nodeID]
	m.mutex.Unlock()

	if !exists {
		return nil, errors.New("node not found")
	}

	var message []byte
	node.DataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
		message, _ = decryptData(msg.Data, m.encryptKey)
	})

	return message, nil
}

// EncryptData encrypts data using AES
func encryptData(data []byte, key []byte) ([]byte, error) {
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

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// DecryptData decrypts data using AES
func decryptData(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// GenerateEncryptionKey generates an encryption key using scrypt or argon2
func GenerateEncryptionKey(password string, salt []byte, useArgon2 bool) ([]byte, error) {
	if useArgon2 {
		return argon2.Key([]byte(password), salt, 3, 32*1024, 4, 32), nil
	}
	return scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
}

// GenerateNodeID generates a unique node ID based on the address
func generateNodeID(address string) string {
	hash := sha256.Sum256([]byte(address))
	return fmt.Sprintf("%x", hash[:])
}

// SmartContract represents a smart contract
type SmartContract struct {
	ContractID string
	Code       string
	State      map[string]interface{}
}

// ExecuteContract executes a smart contract and returns the result
func (m *WebRTCManager) ExecuteContract(contract *SmartContract, input map[string]interface{}) (map[string]interface{}, error) {
	// Simulating smart contract execution
	// In a real-world scenario, this would involve executing the contract's code in a secure environment
	contract.State = input
	return contract.State, nil
}

// Example usage
func main() {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		log.Fatalf("Error generating salt: %v", err)
	}

	encryptKey, err := GenerateEncryptionKey("strongpassword", salt, true)
	if err != nil {
		log.Fatalf("Error generating encryption key: %v", err)
	}

	bootstrapNodes := []string{"node1:8080", "node2:8080"}

	webrtcManager := NewWebRTCManager(encryptKey, bootstrapNodes)

	err = webrtcManager.AddNode("node3:8080")
	if err != nil {
		log.Fatalf("Error adding node: %v", err)
	}

	contract := &SmartContract{
		ContractID: "contract1",
		Code:       "some smart contract code",
		State:      make(map[string]interface{}),
	}

	input := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}

	result, err := webrtcManager.ExecuteContract(contract, input)
	if err != nil {
		log.Fatalf("Error executing contract: %v", err)
	}

	fmt.Printf("Smart contract execution result: %v\n", result)

	message := "Hello, blockchain node!"
	err = webrtcManager.SendMessage(generateNodeID("node3:8080"), []byte(message))
	if err != nil {
		log.Fatalf("Error sending message: %v", err)
	}

	receivedMessage, err := webrtcManager.ReceiveMessage(generateNodeID("node3:8080"))
	if err != nil {
		log.Fatalf("Error receiving message: %v", err)
	}

	fmt.Printf("Received message: %s\n", string(receivedMessage))
}
