package scaling

import (
	"log"
	"sync"
	"time"

	"github.com/synnergy_network/utils"
)

// LoadBalancer structure to hold the nodes and manage load balancing.
type LoadBalancer struct {
	nodes            []*Node
	mu               sync.Mutex
	requestCount     int
	healthCheckInterval time.Duration
}

// Node structure represents a node in the network.
type Node struct {
	ID           string
	Address      string
	HealthStatus bool
	LastChecked  time.Time
}

// NewLoadBalancer initializes a new LoadBalancer.
func NewLoadBalancer(healthCheckInterval time.Duration) *LoadBalancer {
	return &LoadBalancer{
		nodes:            []*Node{},
		healthCheckInterval: healthCheckInterval,
	}
}

// AddNode adds a new node to the load balancer.
func (lb *LoadBalancer) AddNode(node *Node) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.nodes = append(lb.nodes, node)
	log.Printf("Node %s added", node.ID)
}

// RemoveNode removes a node from the load balancer by its ID.
func (lb *LoadBalancer) RemoveNode(nodeID string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for i, node := range lb.nodes {
		if node.ID == nodeID {
			lb.nodes = append(lb.nodes[:i], lb.nodes[i+1:]...)
			log.Printf("Node %s removed", nodeID)
			return
		}
	}
}

// DistributeRequest distributes incoming requests across nodes using a round-robin algorithm.
func (lb *LoadBalancer) DistributeRequest(request string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if len(lb.nodes) == 0 {
		log.Println("No available nodes to handle the request")
		return
	}

	lb.requestCount++
	node := lb.nodes[lb.requestCount%len(lb.nodes)]
	log.Printf("Request %s sent to node %s", request, node.ID)
}

// HealthCheckRoutine performs health checks on all nodes at regular intervals.
func (lb *LoadBalancer) HealthCheckRoutine() {
	for {
		time.Sleep(lb.healthCheckInterval)
		lb.mu.Lock()
		for _, node := range lb.nodes {
			go lb.checkNodeHealth(node)
		}
		lb.mu.Unlock()
	}
}

// checkNodeHealth checks the health of a single node.
func (lb *LoadBalancer) checkNodeHealth(node *Node) {
	// Simulating a health check ping
	healthy := utils.Ping(node.Address)
	node.LastChecked = time.Now()
	node.HealthStatus = healthy
	if healthy {
		log.Printf("Node %s is healthy", node.ID)
	} else {
		log.Printf("Node %s is unhealthy", node.ID)
	}
}

// AutomatedScaling handles dynamic scaling based on the load and network conditions.
func (lb *LoadBalancer) AutomatedScaling() {
	// This is a simplified example. A real implementation would require more sophisticated monitoring and scaling logic.
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if lb.requestCount > len(lb.nodes)*10 { // Example condition to add more nodes
		newNode := &Node{
			ID:      generateNodeID(),
			Address: "new_node_address", // Placeholder for a real address
		}
		lb.AddNode(newNode)
		log.Println("New node added for scaling")
	} else if lb.requestCount < len(lb.nodes)*2 { // Example condition to remove nodes
		if len(lb.nodes) > 1 { // Ensure at least one node remains
			lb.RemoveNode(lb.nodes[len(lb.nodes)-1].ID)
			log.Println("Node removed due to low load")
		}
	}
}

// generateNodeID generates a unique ID for a new node.
func generateNodeID() string {
	return utils.GenerateUUID()
}

// Encryption and Decryption functions using AES for secure data transmission.
func encryptData(data, passphrase string) (string, error) {
	return utils.EncryptAES(data, passphrase)
}

func decryptData(data, passphrase string) (string, error) {
	return utils.DecryptAES(data, passphrase)
}

// Util functions from the utils package (mocked here for the sake of example)
package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

// Ping simulates a health check ping.
func Ping(address string) bool {
	// Simulate a health check (should be replaced with actual health check logic)
	return true
}

// GenerateUUID generates a new UUID.
func GenerateUUID() string {
	// Simple UUID generator (should be replaced with a proper UUID generation method)
	return "new-uuid"
}

// EncryptAES encrypts data using AES.
func EncryptAES(data, passphrase string) (string, error) {
	block, err := aes.NewCipher([]byte(passphrase))
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

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptAES decrypts data using AES.
func DecryptAES(data, passphrase string) (string, error) {
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext, err := hex.DecodeString(data)
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
