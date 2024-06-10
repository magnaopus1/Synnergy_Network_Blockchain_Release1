package networking

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Node represents a network node
type Node struct {
	Address      string
	LastLatency  time.Duration
	LastActive   time.Time
}

// LatencyOptimizationManager manages the optimization of network latency
type LatencyOptimizationManager struct {
	mutex     sync.Mutex
	nodes     map[string]*Node
	latencyFn func(string) (time.Duration, error)
}

// NewLatencyOptimizationManager creates a new LatencyOptimizationManager
func NewLatencyOptimizationManager(latencyFn func(string) (time.Duration, error)) *LatencyOptimizationManager {
	return &LatencyOptimizationManager{
		nodes:     make(map[string]*Node),
		latencyFn: latencyFn,
	}
}

// AddNode adds a new node to the network
func (lom *LatencyOptimizationManager) AddNode(address string) {
	lom.mutex.Lock()
	defer lom.mutex.Unlock()
	lom.nodes[address] = &Node{
		Address:     address,
		LastLatency: 0,
		LastActive:  time.Now(),
	}
}

// RemoveNode removes a node from the network
func (lom *LatencyOptimizationManager) RemoveNode(address string) {
	lom.mutex.Lock()
	defer lom.mutex.Unlock()
	delete(lom.nodes, address)
}

// UpdateNodeLatency updates the latency of a node
func (lom *LatencyOptimizationManager) UpdateNodeLatency(address string) error {
	lom.mutex.Lock()
	defer lom.mutex.Unlock()

	node, exists := lom.nodes[address]
	if !exists {
		return errors.New("node not found")
	}

	latency, err := lom.latencyFn(address)
	if err != nil {
		return err
	}

	node.LastLatency = latency
	node.LastActive = time.Now()
	return nil
}

// FindOptimalNode finds the node with the lowest latency
func (lom *LatencyOptimizationManager) FindOptimalNode() (*Node, error) {
	lom.mutex.Lock()
	defer lom.mutex.Unlock()

	var optimalNode *Node
	for _, node := range lom.nodes {
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

// SimulateSendingMessage simulates sending a message to a node
func SimulateSendingMessage(address string, message string) error {
	fmt.Printf("Sending message to %s: %s\n", address, message)
	// In a real implementation, this would be an actual network call
	return nil
}

// Example usage
func main() {
	// Create a new latency optimization manager
	lom := NewLatencyOptimizationManager(MeasureLatency)

	// Add some nodes
	lom.AddNode("192.168.1.100:8080")
	lom.AddNode("192.168.1.101:8080")
	lom.AddNode("192.168.1.102:8080")

	// Update node latencies
	for address := range lom.nodes {
		if err := lom.UpdateNodeLatency(address); err != nil {
			fmt.Println("Error updating node latency:", err)
		}
	}

	// Find the optimal node to send a message to
	optimalNode, err := lom.FindOptimalNode()
	if err != nil {
		fmt.Println("Error finding optimal node:", err)
		return
	}

	// Simulate sending a message to the optimal node
	message := "Hello, blockchain node!"
	if err := SimulateSendingMessage(optimalNode.Address, message); err != nil {
		fmt.Println("Error sending message:", err)
	}
}
