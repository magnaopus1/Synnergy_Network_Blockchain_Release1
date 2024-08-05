package node

import (
	"errors"
	"math/rand"
	"sync"
	"time"
)

// Node represents a single node in the zk-STARK network.
type Node struct {
	ID       string
	Capacity int
	Load     int
}

// LoadBalancer manages the distribution of workloads across multiple nodes.
type LoadBalancer struct {
	nodes      []*Node
	nodeMutex  sync.Mutex
	maxRetries int
}

// NewLoadBalancer initializes a new LoadBalancer with given nodes.
func NewLoadBalancer(nodes []*Node, maxRetries int) *LoadBalancer {
	return &LoadBalancer{
		nodes:      nodes,
		maxRetries: maxRetries,
	}
}

// AddNode adds a new node to the LoadBalancer.
func (lb *LoadBalancer) AddNode(node *Node) {
	lb.nodeMutex.Lock()
	defer lb.nodeMutex.Unlock()
	lb.nodes = append(lb.nodes, node)
}

// RemoveNode removes a node from the LoadBalancer by ID.
func (lb *LoadBalancer) RemoveNode(nodeID string) error {
	lb.nodeMutex.Lock()
	defer lb.nodeMutex.Unlock()

	for i, node := range lb.nodes {
		if node.ID == nodeID {
			lb.nodes = append(lb.nodes[:i], lb.nodes[i+1:]...)
			return nil
		}
	}
	return errors.New("node not found")
}

// DistributeLoad distributes the workload across the nodes based on their capacity and current load.
func (lb *LoadBalancer) DistributeLoad(workload int) (string, error) {
	lb.nodeMutex.Lock()
	defer lb.nodeMutex.Unlock()

	for i := 0; i < lb.maxRetries; i++ {
		node := lb.selectNode()
		if node != nil && node.Capacity-node.Load >= workload {
			node.Load += workload
			return node.ID, nil
		}
	}

	return "", errors.New("failed to distribute load")
}

// selectNode selects a node based on a weighted random selection algorithm.
func (lb *LoadBalancer) selectNode() *Node {
	totalCapacity := 0
	for _, node := range lb.nodes {
		totalCapacity += node.Capacity - node.Load
	}

	if totalCapacity == 0 {
		return nil
	}

	rand.Seed(time.Now().UnixNano())
	randomPoint := rand.Intn(totalCapacity)

	for _, node := range lb.nodes {
		randomPoint -= node.Capacity - node.Load
		if randomPoint <= 0 {
			return node
		}
	}

	return nil
}

// UpdateNodeLoad updates the load of a specific node by ID.
func (lb *LoadBalancer) UpdateNodeLoad(nodeID string, load int) error {
	lb.nodeMutex.Lock()
	defer lb.nodeMutex.Unlock()

	for _, node := range lb.nodes {
		if node.ID == nodeID {
			node.Load = load
			return nil
		}
	}

	return errors.New("node not found")
}

// BalanceLoad balances the load across all nodes by redistributing workloads.
func (lb *LoadBalancer) BalanceLoad() {
	lb.nodeMutex.Lock()
	defer lb.nodeMutex.Unlock()

	totalLoad := 0
	for _, node := range lb.nodes {
		totalLoad += node.Load
	}

	averageLoad := totalLoad / len(lb.nodes)

	for _, node := range lb.nodes {
		node.Load = averageLoad
	}
}

// MonitorNodes monitors the nodes' status and removes nodes that are unresponsive.
func (lb *LoadBalancer) MonitorNodes() {
	for {
		time.Sleep(30 * time.Second)
		lb.nodeMutex.Lock()
		for i := len(lb.nodes) - 1; i >= 0; i-- {
			node := lb.nodes[i]
			if !lb.isNodeResponsive(node) {
				lb.nodes = append(lb.nodes[:i], lb.nodes[i+1:]...)
			}
		}
		lb.nodeMutex.Unlock()
	}
}

// isNodeResponsive checks if a node is responsive.
func (lb *LoadBalancer) isNodeResponsive(node *Node) bool {
	// In a real-world implementation, this would involve network checks or heartbeat signals.
	// Here, we simulate with a random chance of failure.
	return rand.Float32() > 0.1
}

// SecureCommunication ensures that communication between nodes is secure using encryption.
func (lb *LoadBalancer) SecureCommunication(message string) (string, error) {
	encryptedMessage, err := encryptMessage(message)
	if err != nil {
		return "", err
	}
	return encryptedMessage, nil
}

// encryptMessage is a placeholder for an encryption method.
func encryptMessage(message string) (string, error) {
	// In a real-world implementation, use a proper encryption algorithm such as AES or ChaCha20-Poly1305.
	// Here, we simulate encryption by reversing the string.
	runes := []rune(message)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes), nil
}

