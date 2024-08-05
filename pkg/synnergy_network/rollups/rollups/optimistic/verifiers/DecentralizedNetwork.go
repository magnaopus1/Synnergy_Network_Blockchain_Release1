package verifiers

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/scrypt"
)

// Node represents a node in the decentralized network.
type Node struct {
	ID         string
	PublicKey  string
	Reputation int
}

// DecentralizedNetwork handles the network of decentralized nodes for verification.
type DecentralizedNetwork struct {
	mu         sync.Mutex
	nodes      map[string]*Node
	networkLog []string
}

// NewDecentralizedNetwork initializes a new DecentralizedNetwork instance.
func NewDecentralizedNetwork() *DecentralizedNetwork {
	return &DecentralizedNetwork{
		nodes: make(map[string]*Node),
	}
}

// AddNode adds a new node to the decentralized network.
func (dn *DecentralizedNetwork) AddNode(publicKey string) (string, error) {
	dn.mu.Lock()
	defer dn.mu.Unlock()

	nodeID := dn.generateNodeID(publicKey)
	if _, exists := dn.nodes[nodeID]; exists {
		return "", errors.New("node already exists")
	}

	node := &Node{
		ID:         nodeID,
		PublicKey:  publicKey,
		Reputation: 100, // Starting reputation
	}

	dn.nodes[nodeID] = node
	dn.networkLog = append(dn.networkLog, fmt.Sprintf("Node Added: %+v", node))

	return nodeID, nil
}

// RemoveNode removes a node from the decentralized network.
func (dn *DecentralizedNetwork) RemoveNode(nodeID string) error {
	dn.mu.Lock()
	defer dn.mu.Unlock()

	if _, exists := dn.nodes[nodeID]; !exists {
		return errors.New("node not found")
	}

	delete(dn.nodes, nodeID)
	dn.networkLog = append(dn.networkLog, fmt.Sprintf("Node Removed: %s", nodeID))

	return nil
}

// GetNode retrieves a node by its ID.
func (dn *DecentralizedNetwork) GetNode(nodeID string) (*Node, error) {
	dn.mu.Lock()
	defer dn.mu.Unlock()

	node, exists := dn.nodes[nodeID]
	if !exists {
		return nil, errors.New("node not found")
	}

	return node, nil
}

// ListNodes lists all nodes in the decentralized network.
func (dn *DecentralizedNetwork) ListNodes() []*Node {
	dn.mu.Lock()
	defer dn.mu.Unlock()

	nodes := []*Node{}
	for _, node := range dn.nodes {
		nodes = append(nodes, node)
	}

	return nodes
}

// UpdateReputation updates the reputation of a node.
func (dn *DecentralizedNetwork) UpdateReputation(nodeID string, change int) error {
	dn.mu.Lock()
	defer dn.mu.Unlock()

	node, exists := dn.nodes[nodeID]
	if !exists {
		return errors.New("node not found")
	}

	node.Reputation += change
	if node.Reputation < 0 {
		node.Reputation = 0
	}
	dn.networkLog = append(dn.networkLog, fmt.Sprintf("Node Reputation Updated: %+v", node))

	return nil
}

// generateNodeID generates a unique node ID using scrypt.
func (dn *DecentralizedNetwork) generateNodeID(publicKey string) string {
	salt := []byte(publicKey)
	dk, _ := scrypt.Key([]byte(fmt.Sprintf("%d", time.Now().UnixNano())), salt, 16384, 8, 1, 32)
	return hex.EncodeToString(dk)
}

// EncryptNodeData encrypts node data using SHA-256.
func (dn *DecentralizedNetwork) EncryptNodeData(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// PrintNetworkLog prints the network log.
func (dn *DecentralizedNetwork) PrintNetworkLog() {
	dn.mu.Lock()
	defer dn.mu.Unlock()

	fmt.Println("Network Log:")
	for _, log := range dn.networkLog {
		fmt.Println(log)
	}
}

// ExportNetworkMetrics exports network metrics for monitoring tools.
func (dn *DecentralizedNetwork) ExportNetworkMetrics() map[string]interface{} {
	dn.mu.Lock()
	defer dn.mu.Unlock()

	totalNodes := len(dn.nodes)
	totalReputation := 0
	for _, node := range dn.nodes {
		totalReputation += node.Reputation
	}

	metrics := map[string]interface{}{
		"totalNodes":       totalNodes,
		"averageReputation": float64(totalReputation) / float64(totalNodes),
	}

	return metrics
}
