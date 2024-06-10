package networking

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// Node represents a network node
type Node struct {
	ID           string
	Address      string
	LastLatency  time.Duration
	LastActive   time.Time
	Reputation   int
	Geolocation  string
	LatencyScore float64
}

// SDNManager manages the software-defined networking functionalities
type SDNManager struct {
	mutex          sync.Mutex
	nodes          map[string]*Node
	latencyFn      func(string) (time.Duration, error)
	listener       net.Listener
	stopChan       chan struct{}
	encryptKey     []byte
	bootstrapNodes []string
}

// NewSDNManager creates a new SDNManager
func NewSDNManager(latencyFn func(string) (time.Duration, error), encryptKey []byte, bootstrapNodes []string) *SDNManager {
	return &SDNManager{
		nodes:          make(map[string]*Node),
		latencyFn:      latencyFn,
		stopChan:       make(chan struct{}),
		encryptKey:     encryptKey,
		bootstrapNodes: bootstrapNodes,
	}
}

// AddNode adds a new node to the network
func (sdn *SDNManager) AddNode(address string, geolocation string) {
	nodeID := generateNodeID(address)
	sdn.mutex.Lock()
	defer sdn.mutex.Unlock()
	sdn.nodes[nodeID] = &Node{
		ID:           nodeID,
		Address:      address,
		LastLatency:  0,
		LastActive:   time.Now(),
		Reputation:   100, // Starting reputation score
		Geolocation:  geolocation,
		LatencyScore: 0,
	}
}

// RemoveNode removes a node from the network
func (sdn *SDNManager) RemoveNode(nodeID string) {
	sdn.mutex.Lock()
	defer sdn.mutex.Unlock()
	delete(sdn.nodes, nodeID)
}

// UpdateNodeLatency updates the latency of a node
func (sdn *SDNManager) UpdateNodeLatency(nodeID string) error {
	sdn.mutex.Lock()
	defer sdn.mutex.Unlock()

	node, exists := sdn.nodes[nodeID]
	if !exists {
		return errors.New("node not found")
	}

	latency, err := sdn.latencyFn(node.Address)
	if err != nil {
		return err
	}

	node.LastLatency = latency
	node.LastActive = time.Now()
	node.LatencyScore = calculateLatencyScore(latency)
	return nil
}

// FindOptimalNode finds the node with the best score
func (sdn *SDNManager) FindOptimalNode() (*Node, error) {
	sdn.mutex.Lock()
	defer sdn.mutex.Unlock()

	var optimalNode *Node
	for _, node := range sdn.nodes {
		if optimalNode == nil || node.LatencyScore > optimalNode.LatencyScore {
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
func (sdn *SDNManager) StartListening(port string) error {
	listener, err := net.Listen("tcp", port)
	if err != nil {
		return err
	}
	sdn.listener = listener

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-sdn.stopChan:
					return
				default:
					continue
				}
			}
			go sdn.handleConnection(conn)
		}
	}()

	return nil
}

// StopListening stops listening for incoming connections
func (sdn *SDNManager) StopListening() {
	close(sdn.stopChan)
	if sdn.listener != nil {
		sdn.listener.Close()
	}
}

// handleConnection handles an incoming connection
func (sdn *SDNManager) handleConnection(conn net.Conn) {
	defer conn.Close()
	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			return
		}
		data := buffer[:n]
		decryptedData, err := sdn.decryptData(data)
		if err != nil {
			return
		}
		fmt.Println("Received message:", string(decryptedData))
	}
}

// EncryptData encrypts data using AES
func (sdn *SDNManager) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(sdn.encryptKey)
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
func (sdn *SDNManager) decryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(sdn.encryptKey)
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

// Example usage
func main() {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		fmt.Println("Error generating salt:", err)
		return
	}

	encryptKey, err := GenerateEncryptionKey("strongpassword", salt, true)
	if err != nil {
		fmt.Println("Error generating encryption key:", err)
		return
	}

	// Bootstrap nodes
	bootstrapNodes := []string{"192.168.1.100:8080", "192.168.1.101:8080"}

	// Create a new SDN manager
	sdn := NewSDNManager(MeasureLatency, encryptKey, bootstrapNodes)

	// Add some nodes
	sdn.AddNode("192.168.1.102:8080", "US")
	sdn.AddNode("192.168.1.103:8080", "EU")
	sdn.AddNode("192.168.1.104:8080", "AS")

	// Update node latencies
	for nodeID := range sdn.nodes {
		if err := sdn.UpdateNodeLatency(nodeID); err != nil {
			fmt.Println("Error updating node latency:", err)
		}
	}

	// Find the optimal node to send a message to
	optimalNode, err := sdn.FindOptimalNode()
	if err != nil {
		fmt.Println("Error finding optimal node:", err)
		return
	}

	// Start listening for incoming connections
	if err := sdn.StartListening(":8080"); err != nil {
		fmt.Println("Error starting listener:", err)
		return
	}
	defer sdn.StopListening()

	// Simulate sending a message to the optimal node
	message := "Hello, blockchain node!"
	encryptedMessage, err := sdn.encryptData([]byte(message))
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

// Helper functions
func generateNodeID(address string) string {
	hash := sha256.Sum256([]byte(address))
	return hex.EncodeToString(hash[:])
}

func calculateLatencyScore(latency time.Duration) float64 {
	// Example calculation: inversely proportional to latency
	return 1 / float64(latency.Milliseconds())
}
