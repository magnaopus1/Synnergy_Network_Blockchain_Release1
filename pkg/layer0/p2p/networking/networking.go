package networking

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Constants for networking
const (
	SaltSize = 32
	KeySize  = 32
)

// Node represents a network node
type Node struct {
	Address     string
	LastLatency time.Duration
	LastActive  time.Time
}

// NetworkingManager manages the networking functionalities
type NetworkingManager struct {
	mutex      sync.Mutex
	nodes      map[string]*Node
	latencyFn  func(string) (time.Duration, error)
	listener   net.Listener
	stopChan   chan struct{}
	encryptKey []byte
}

// NewNetworkingManager creates a new NetworkingManager
func NewNetworkingManager(latencyFn func(string) (time.Duration, error), encryptKey []byte) *NetworkingManager {
	return &NetworkingManager{
		nodes:      make(map[string]*Node),
		latencyFn:  latencyFn,
		stopChan:   make(chan struct{}),
		encryptKey: encryptKey,
	}
}

// AddNode adds a new node to the network
func (nm *NetworkingManager) AddNode(address string) {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()
	nm.nodes[address] = &Node{
		Address:     address,
		LastLatency: 0,
		LastActive:  time.Now(),
	}
}

// RemoveNode removes a node from the network
func (nm *NetworkingManager) RemoveNode(address string) {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()
	delete(nm.nodes, address)
}

// UpdateNodeLatency updates the latency of a node
func (nm *NetworkingManager) UpdateNodeLatency(address string) error {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()

	node, exists := nm.nodes[address]
	if !exists {
		return errors.New("node not found")
	}

	latency, err := nm.latencyFn(address)
	if err != nil {
		return err
	}

	node.LastLatency = latency
	node.LastActive = time.Now()
	return nil
}

// FindOptimalNode finds the node with the lowest latency
func (nm *NetworkingManager) FindOptimalNode() (*Node, error) {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()

	var optimalNode *Node
	for _, node := range nm.nodes {
		if optimalNode == nil || node.LastLatency < optimalNode.LastLatency {
			optimalNode = node
		}
	}

	if optimalNode == nil {
		return nil, errors.New("no nodes available")
	}

	return optimalNode, nil
}

// MeasureLatency measures the latency to a given address
func MeasureLatency(address string) (time.Duration, error) {
	start := time.Now()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return 0, err
	}
	conn.Close()
	latency := time.Since(start)
	return latency, nil
}

// StartListening starts listening for incoming connections
func (nm *NetworkingManager) StartListening(port string) error {
	listener, err := net.Listen("tcp", port)
	if err != nil {
		return err
	}
	nm.listener = listener

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-nm.stopChan:
					return
				default:
					continue
				}
			}
			go nm.handleConnection(conn)
		}
	}()

	return nil
}

// StopListening stops listening for incoming connections
func (nm *NetworkingManager) StopListening() {
	close(nm.stopChan)
	if nm.listener != nil {
		nm.listener.Close()
	}
}

// handleConnection handles an incoming connection
func (nm *NetworkingManager) handleConnection(conn net.Conn) {
	defer conn.Close()
	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			return
		}
		data := buffer[:n]
		decryptedData, err := nm.decryptData(data)
		if err != nil {
			return
		}
		fmt.Println("Received message:", string(decryptedData))
	}
}

// EncryptData encrypts data using AES
func (nm *NetworkingManager) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(nm.encryptKey)
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
func (nm *NetworkingManager) decryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(nm.encryptKey)
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

// GenerateEncryptionKey generates an encryption key using scrypt
func GenerateEncryptionKey(password string, salt []byte) ([]byte, error) {
	key, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, KeySize)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Example usage
func main() {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		fmt.Println("Error generating salt:", err)
		return
	}

	encryptKey, err := GenerateEncryptionKey("strongpassword", salt)
	if err != nil {
		fmt.Println("Error generating encryption key:", err)
		return
	}

	// Create a new networking manager
	nm := NewNetworkingManager(MeasureLatency, encryptKey)

	// Add some nodes
	nm.AddNode("192.168.1.100:8080")
	nm.AddNode("192.168.1.101:8080")
	nm.AddNode("192.168.1.102:8080")

	// Update node latencies
	for address := range nm.nodes {
		if err := nm.UpdateNodeLatency(address); err != nil {
			fmt.Println("Error updating node latency:", err)
		}
	}

	// Find the optimal node to send a message to
	optimalNode, err := nm.FindOptimalNode()
	if err != nil {
		fmt.Println("Error finding optimal node:", err)
		return
	}

	// Start listening for incoming connections
	if err := nm.StartListening(":8080"); err != nil {
		fmt.Println("Error starting listener:", err)
		return
	}
	defer nm.StopListening()

	// Simulate sending a message to the optimal node
	message := "Hello, blockchain node!"
	encryptedMessage, err := nm.encryptData([]byte(message))
	if err != nil {
		fmt.Println("Error encrypting message:", err)
		return
	}

	conn, err := net.Dial("tcp", optimalNode.Address)
	if err != nil {
		fmt.Println("Error connecting to node:", err)
		return
	}
	defer conn.Close()

	if _, err := conn.Write(encryptedMessage); err != nil {
		fmt.Println("Error sending message:", err)
	}
}
