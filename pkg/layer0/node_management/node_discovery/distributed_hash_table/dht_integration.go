package distributed_hash_table

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// Node represents a node in the DHT network.
type Node struct {
	ID        string
	Address   string
	LastSeen  time.Time
	PublicKey string
}

// DHT represents the Distributed Hash Table.
type DHT struct {
	mu    sync.Mutex
	nodes map[string]*Node
}

// NewDHT creates a new instance of the DHT.
func NewDHT() *DHT {
	return &DHT{
		nodes: make(map[string]*Node),
	}
}

// AddNode adds a new node to the DHT.
func (d *DHT) AddNode(node *Node) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nodes[node.ID] = node
}

// RemoveNode removes a node from the DHT.
func (d *DHT) RemoveNode(nodeID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.nodes, nodeID)
}

// FindNode finds a node in the DHT by its ID.
func (d *DHT) FindNode(nodeID string) (*Node, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	node, exists := d.nodes[nodeID]
	return node, exists
}

// DiscoverPeers discovers peers within the DHT based on a given node ID.
func (d *DHT) DiscoverPeers(targetID string) ([]*Node, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	targetInt := new(big.Int)
	targetInt.SetString(targetID, 16)

	var closestNodes []*Node
	for _, node := range d.nodes {
		nodeInt := new(big.Int)
		nodeInt.SetString(node.ID, 16)

		distance := new(big.Int)
		distance.Xor(targetInt, nodeInt)

		closestNodes = append(closestNodes, node)
	}

	return closestNodes, nil
}

// BootstrapNode bootstraps a new node into the network by connecting to a seed node.
func (d *DHT) BootstrapNode(seedNodeAddr string) error {
	conn, err := net.Dial("tcp", seedNodeAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	seedNode := &Node{
		ID:       generateNodeID(seedNodeAddr),
		Address:  seedNodeAddr,
		LastSeen: time.Now(),
	}

	d.AddNode(seedNode)
	return nil
}

// generateNodeID generates a unique node ID based on the node's address.
func generateNodeID(address string) string {
	hash := sha256.New()
	hash.Write([]byte(address))
	return hex.EncodeToString(hash.Sum(nil))
}

// NodeHealth represents the health status of a node.
type NodeHealth struct {
	CPUUsage    float64
	MemoryUsage float64
	Latency     time.Duration
}

// Heartbeat represents a heartbeat message sent by nodes to indicate their status.
type Heartbeat struct {
	NodeID    string
	Timestamp time.Time
	Health    NodeHealth
}

// HealthCheckAPI represents the health check API for nodes.
type HealthCheckAPI struct {
	dht *DHT
}

// NewHealthCheckAPI creates a new HealthCheckAPI.
func NewHealthCheckAPI(dht *DHT) *HealthCheckAPI {
	return &HealthCheckAPI{dht: dht}
}

// SendHeartbeat sends a heartbeat message to the DHT.
func (api *HealthCheckAPI) SendHeartbeat(nodeID string, health NodeHealth) error {
	api.dht.mu.Lock()
	defer api.dht.mu.Unlock()

	node, exists := api.dht.nodes[nodeID]
	if !exists {
		return errors.New("node not found")
	}

	node.LastSeen = time.Now()
	// Update node health status (CPU, Memory, Latency)
	// Placeholder for logic to update node's health status in DHT.

	return nil
}

// QueryNodeHealth queries the health status of a node.
func (api *HealthCheckAPI) QueryNodeHealth(nodeID string) (*NodeHealth, error) {
	api.dht.mu.Lock()
	defer api.dht.mu.Unlock()

	node, exists := api.dht.nodes[nodeID]
	if !exists {
		return nil, errors.New("node not found")
	}

	// Placeholder for logic to return actual health status.
	health := &NodeHealth{
		CPUUsage:    0.5,
		MemoryUsage: 0.4,
		Latency:     10 * time.Millisecond,
	}

	return health, nil
}

// QuarantineNode quarantines a node that exhibits abnormal behavior.
func (api *HealthCheckAPI) QuarantineNode(nodeID string) error {
	api.dht.mu.Lock()
	defer api.dht.mu.Unlock()

	node, exists := api.dht.nodes[nodeID]
	if !exists {
		return errors.New("node not found")
	}

	// Placeholder for logic to quarantine the node.
	fmt.Printf("Node %s is quarantined due to abnormal behavior\n", nodeID)

	return nil
}

// NodeRegistrationAPI represents the API for node registration.
type NodeRegistrationAPI struct {
	dht *DHT
}

// NewNodeRegistrationAPI creates a new NodeRegistrationAPI.
func NewNodeRegistrationAPI(dht *DHT) *NodeRegistrationAPI {
	return &NodeRegistrationAPI{dht: dht}
}

// RegisterNode registers a new node in the DHT.
func (api *NodeRegistrationAPI) RegisterNode(node *Node) error {
	api.dht.mu.Lock()
	defer api.dht.mu.Unlock()

	if _, exists := api.dht.nodes[node.ID]; exists {
		return errors.New("node already registered")
	}

	// Placeholder for additional registration logic (e.g., identity verification).
	api.dht.nodes[node.ID] = node

	return nil
}

// PoWChallenge represents a proof-of-work challenge for node registration.
type PoWChallenge struct {
	Challenge   string
	Difficulty  int
	Solution    string
	SubmittedBy string
}

// GeneratePoWChallenge generates a new proof-of-work challenge.
func GeneratePoWChallenge(difficulty int) *PoWChallenge {
	challenge := generateRandomString(32)
	return &PoWChallenge{
		Challenge:  challenge,
		Difficulty: difficulty,
	}
}

// ValidatePoWChallenge validates a proof-of-work challenge solution.
func ValidatePoWChallenge(challenge *PoWChallenge, solution string) bool {
	// Placeholder for proof-of-work validation logic.
	// In real implementation, check if solution meets the difficulty requirements.
	return true
}

// generateRandomString generates a random string of the given length.
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}
