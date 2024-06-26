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

// TCPIPNetworking manages the TCP/IP networking functionalities
type TCPIPNetworking struct {
	mutex          sync.Mutex
	nodes          map[string]*Node
	latencyFn      func(string) (time.Duration, error)
	listener       net.Listener
	stopChan       chan struct{}
	encryptKey     []byte
	bootstrapNodes []string
	connectionPool map[string]net.Conn
}

// NewTCPIPNetworking creates a new TCPIPNetworking manager
func NewTCPIPNetworking(latencyFn func(string) (time.Duration, error), encryptKey []byte, bootstrapNodes []string) *TCPIPNetworking {
	return &TCPIPNetworking{
		nodes:          make(map[string]*Node),
		latencyFn:      latencyFn,
		stopChan:       make(chan struct{}),
		encryptKey:     encryptKey,
		bootstrapNodes: bootstrapNodes,
		connectionPool: make(map[string]net.Conn),
	}
}

// AddNode adds a new node to the network
func (net *TCPIPNetworking) AddNode(address string, geolocation string) {
	nodeID := generateNodeID(address)
	net.mutex.Lock()
	defer net.mutex.Unlock()
	net.nodes[nodeID] = &Node{
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
func (net *TCPIPNetworking) RemoveNode(nodeID string) {
	net.mutex.Lock()
	defer net.mutex.Unlock()
	delete(net.nodes, nodeID)
}

// UpdateNodeLatency updates the latency of a node
func (net *TCPIPNetworking) UpdateNodeLatency(nodeID string) error {
	net.mutex.Lock()
	defer net.mutex.Unlock()

	node, exists := net.nodes[nodeID]
	if !exists {
		return errors.New("node not found")
	}

	latency, err := net.latencyFn(node.Address)
	if err != nil {
		return err
	}

	node.LastLatency = latency
	node.LastActive = time.Now()
	node.LatencyScore = calculateLatencyScore(latency)
	return nil
}

// FindOptimalNode finds the node with the best score
func (net *TCPIPNetworking) FindOptimalNode() (*Node, error) {
	net.mutex.Lock()
	defer net.mutex.Unlock()

	var optimalNode *Node
	for _, node := range net.nodes {
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
func (net *TCPIPNetworking) StartListening(port string) error {
	listener, err := net.Listen("tcp", port)
	if err != nil {
		return err
	}
	net.listener = listener

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-net.stopChan:
					return
				default:
					continue
				}
			}
			go net.handleConnection(conn)
		}
	}()

	return nil
}

// StopListening stops listening for incoming connections
func (net *TCPIPNetworking) StopListening() {
	close(net.stopChan)
	if net.listener != nil {
		net.listener.Close()
	}
}

// handleConnection handles an incoming connection
func (net *TCPIPNetworking) handleConnection(conn net.Conn) {
	defer conn.Close()
	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			return
		}
		data := buffer[:n]
		decryptedData, err := net.decryptData(data)
		if err != nil {
			return
		}
		fmt.Println("Received message:", string(decryptedData))
	}
}

// EncryptData encrypts data using AES
func (net *TCPIPNetworking) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(net.encryptKey)
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
func (net *TCPIPNetworking) decryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(net.encryptKey)
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

// GetOrCreateConnection gets an existing connection or creates a new one
func (net *TCPIPNetworking) GetOrCreateConnection(address string) (net.Conn, error) {
	net.mutex.Lock()
	defer net.mutex.Unlock()

	conn, exists := net.connectionPool[address]
	if !exists || conn == nil {
		var err error
		conn, err = net.Dial("tcp", address)
		if err != nil {
			return nil, err
		}
		net.connectionPool[address] = conn
	}
	return conn, nil
}

// SendMessage sends an encrypted message to a node
func (net *TCPIPNetworking) SendMessage(node *Node, message []byte) error {
	conn, err := net.GetOrCreateConnection(node.Address)
	if err != nil {
		return err
	}

	encryptedMessage, err := net.encryptData(message)
	if err != nil {
		return err
	}

	_, err = conn.Write(encryptedMessage)
	return err
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

	// Create a new TCPIPNetworking manager
	net := NewTCPIPNetworking(MeasureLatency, encryptKey, bootstrapNodes)

	// Add some nodes
	net.AddNode("192.168.1.102:8080", "US")
	net.AddNode("192.168.1.103:8080", "EU")
	net.AddNode("192.168.1.104:8080", "AS")

	// Update node latencies
	for nodeID := range net.nodes {
		if err := net.UpdateNodeLatency(nodeID); err != nil {
			fmt.Println("Error updating node latency:", err)
		}
	}

	// Find the optimal node to send a message to
	optimalNode, err := net.FindOptimalNode()
	if err != nil {
		fmt.Println("Error finding optimal node:", err)
		return
	}

	// Start listening for incoming connections
	if err := net.StartListening(":8080"); err != nil {
		fmt.Println("Error starting listener:", err)
		return
	}
	defer net.StopListening()

	// Simulate sending a message to the optimal node
	message := "Hello, blockchain node!"
	if err := net.SendMessage(optimalNode, []byte(message)); err != nil {
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
