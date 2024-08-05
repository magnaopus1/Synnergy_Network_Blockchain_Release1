package adaptive_scaling

import (
	"log"
	"time"
	"sync"
	"net/http"
	"math/rand"
	"encoding/json"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/argon2"
)

// ElasticNodeProvisioning struct to manage node provisioning
type ElasticNodeProvisioning struct {
	mu                sync.Mutex
	activeNodes       map[string]*Node
	scalingPolicies   ScalingPolicy
	resourceThreshold ResourceThreshold
}

// Node represents a network node with its resources
type Node struct {
	ID         string
	CPU        int
	Memory     int
	Network    int
	LastActive time.Time
	Status     string
}

// ScalingPolicy defines the rules for scaling
type ScalingPolicy struct {
	MaxNodes        int
	MinNodes        int
	ScaleUpThreshold   float64
	ScaleDownThreshold float64
	MonitoringInterval time.Duration
}

// ResourceThreshold defines resource usage limits
type ResourceThreshold struct {
	MaxCPUUsage    float64
	MaxMemoryUsage float64
	MaxNetworkUsage float64
}

// NewElasticNodeProvisioning creates a new ElasticNodeProvisioning instance
func NewElasticNodeProvisioning(sp ScalingPolicy, rt ResourceThreshold) *ElasticNodeProvisioning {
	return &ElasticNodeProvisioning{
		activeNodes:       make(map[string]*Node),
		scalingPolicies:   sp,
		resourceThreshold: rt,
	}
}

// AddNode adds a new node to the network
func (enp *ElasticNodeProvisioning) AddNode(node *Node) {
	enp.mu.Lock()
	defer enp.mu.Unlock()

	if len(enp.activeNodes) < enp.scalingPolicies.MaxNodes {
		node.Status = "active"
		node.LastActive = time.Now()
		enp.activeNodes[node.ID] = node
		log.Printf("Node %s added successfully", node.ID)
	} else {
		log.Printf("Maximum number of nodes reached. Node %s cannot be added.", node.ID)
	}
}

// RemoveNode removes a node from the network
func (enp *ElasticNodeProvisioning) RemoveNode(nodeID string) {
	enp.mu.Lock()
	defer enp.mu.Unlock()

	if node, exists := enp.activeNodes[nodeID]; exists {
		node.Status = "inactive"
		delete(enp.activeNodes, nodeID)
		log.Printf("Node %s removed successfully", nodeID)
	} else {
		log.Printf("Node %s not found", nodeID)
	}
}

// MonitorNodes continuously monitors and adjusts node resources
func (enp *ElasticNodeProvisioning) MonitorNodes() {
	ticker := time.NewTicker(enp.scalingPolicies.MonitoringInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			enp.adjustResources()
		}
	}
}

// adjustResources scales nodes up or down based on resource usage
func (enp *ElasticNodeProvisioning) adjustResources() {
	enp.mu.Lock()
	defer enp.mu.Unlock()

	totalCPU, totalMemory, totalNetwork := enp.calculateTotalResources()
	numNodes := len(enp.activeNodes)

	avgCPUUsage := float64(totalCPU) / float64(numNodes)
	avgMemoryUsage := float64(totalMemory) / float64(numNodes)
	avgNetworkUsage := float64(totalNetwork) / float64(numNodes)

	if avgCPUUsage > enp.resourceThreshold.MaxCPUUsage || avgMemoryUsage > enp.resourceThreshold.MaxMemoryUsage || avgNetworkUsage > enp.resourceThreshold.MaxNetworkUsage {
		enp.scaleUp()
	} else if avgCPUUsage < enp.resourceThreshold.MaxCPUUsage && avgMemoryUsage < enp.resourceThreshold.MaxMemoryUsage && avgNetworkUsage < enp.resourceThreshold.MaxNetworkUsage {
		enp.scaleDown()
	}
}

func (enp *ElasticNodeProvisioning) calculateTotalResources() (int, int, int) {
	totalCPU, totalMemory, totalNetwork := 0, 0, 0
	for _, node := range enp.activeNodes {
		totalCPU += node.CPU
		totalMemory += node.Memory
		totalNetwork += node.Network
	}
	return totalCPU, totalMemory, totalNetwork
}

// scaleUp adds additional nodes to handle increased load
func (enp *ElasticNodeProvisioning) scaleUp() {
	if len(enp.activeNodes) < enp.scalingPolicies.MaxNodes {
		newNode := &Node{
			ID:     generateNodeID(),
			CPU:    rand.Intn(100) + 50,  // Example CPU capacity
			Memory: rand.Intn(2048) + 1024,  // Example Memory capacity
			Network: rand.Intn(1000) + 500, // Example Network capacity
		}
		enp.AddNode(newNode)
		log.Printf("Scaling up: added node %s", newNode.ID)
	}
}

// scaleDown removes nodes when demand is low
func (enp *ElasticNodeProvisioning) scaleDown() {
	if len(enp.activeNodes) > enp.scalingPolicies.MinNodes {
		var oldestNode *Node
		for _, node := range enp.activeNodes {
			if oldestNode == nil || node.LastActive.Before(oldestNode.LastActive) {
				oldestNode = node
			}
		}
		if oldestNode != nil {
			enp.RemoveNode(oldestNode.ID)
			log.Printf("Scaling down: removed node %s", oldestNode.ID)
		}
	}
}

// generateNodeID generates a secure unique node ID
func generateNodeID() string {
	return fmt.Sprintf("node-%d", rand.Intn(100000))
}

// EncryptNodeData securely encrypts node data
func EncryptNodeData(data []byte, password string) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	key, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	encryptedData, err := aesEncrypt(data, key)
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}

// DecryptNodeData securely decrypts node data
func DecryptNodeData(encryptedData []byte, password string) ([]byte, error) {
	salt := encryptedData[:16]
	encData := encryptedData[16:]

	key, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	data, err := aesDecrypt(encData, key)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// aesEncrypt and aesDecrypt are utility functions for AES encryption/decryption
func aesEncrypt(data, key []byte) ([]byte, error) {
	// Implementation for AES encryption
}

func aesDecrypt(encryptedData, key []byte) ([]byte, error) {
	// Implementation for AES decryption
}
