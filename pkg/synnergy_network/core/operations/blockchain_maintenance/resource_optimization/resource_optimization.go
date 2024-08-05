package resource_optimization

import (
	"fmt"
	"log"
	"math/rand"
	"time"
)

// Node represents a node in the blockchain network
type Node struct {
	ID       string
	Load     int
	Capacity int
	Active   bool
}

// LoadBalancer is responsible for distributing load across nodes
type LoadBalancer struct {
	nodes           []Node
	history         map[string][]int
	optimizationLog []string
}

// NewLoadBalancer initializes a new LoadBalancer
func NewLoadBalancer(nodes []Node) *LoadBalancer {
	return &LoadBalancer{
		nodes:   nodes,
		history: make(map[string][]int),
	}
}

// AddNode adds a new node to the load balancer
func (lb *LoadBalancer) AddNode(node Node) {
	lb.nodes = append(lb.nodes, node)
	log.Printf("Node added: %s", node.ID)
}

// RemoveNode removes a node from the load balancer by ID
func (lb *LoadBalancer) RemoveNode(nodeID string) {
	for i, node := range lb.nodes {
		if node.ID == nodeID {
			lb.nodes = append(lb.nodes[:i], lb.nodes[i+1:]...)
			log.Printf("Node removed: %s", nodeID)
			return
		}
	}
	log.Printf("Node not found: %s", nodeID)
}

// DistributeLoad distributes the given load across the nodes
func (lb *LoadBalancer) DistributeLoad(load int) {
	totalCapacity := lb.getTotalActiveCapacity()
	if totalCapacity == 0 {
		log.Println("No active nodes available to distribute load")
		return
	}

	for i := range lb.nodes {
		if lb.nodes[i].Active {
			allocation := load * lb.nodes[i].Capacity / totalCapacity
			lb.nodes[i].Load += allocation
			lb.history[lb.nodes[i].ID] = append(lb.history[lb.nodes[i].ID], lb.nodes[i].Load)
			load -= allocation
		}
	}

	lb.optimizeLoadDistribution()
	lb.logOptimization()
}

// getTotalActiveCapacity calculates the total capacity of all active nodes
func (lb *LoadBalancer) getTotalActiveCapacity() int {
	total := 0
	for _, node := range lb.nodes {
		if node.Active {
			total += node.Capacity
		}
	}
	return total
}

// optimizeLoadDistribution applies optimization algorithms to balance the load more efficiently
func (lb *LoadBalancer) optimizeLoadDistribution() {
	// Example optimization: Randomly shuffle nodes and re-distribute load
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(lb.nodes), func(i, j int) { lb.nodes[i], lb.nodes[j] = lb.nodes[j], lb.nodes[i] })

	for _, node := range lb.nodes {
		if node.Load > node.Capacity {
			excessLoad := node.Load - node.Capacity
			node.Load = node.Capacity
			lb.DistributeLoad(excessLoad)
		}
	}
}

// logOptimization logs the optimization process for audit and analysis
func (lb *LoadBalancer) logOptimization() {
	logEntry := fmt.Sprintf("Load distribution at %s: ", time.Now().Format(time.RFC3339))
	for _, node := range lb.nodes {
		logEntry += fmt.Sprintf("Node %s: %d/%d ", node.ID, node.Load, node.Capacity)
	}
	lb.optimizationLog = append(lb.optimizationLog, logEntry)
	log.Println(logEntry)
}

// GetLoadHistory returns the load history of a specific node
func (lb *LoadBalancer) GetLoadHistory(nodeID string) []int {
	return lb.history[nodeID]
}

// Example usage
func main() {
	nodes := []Node{
		{ID: "Node1", Load: 0, Capacity: 100, Active: true},
		{ID: "Node2", Load: 0, Capacity: 150, Active: true},
		{ID: "Node3", Load: 0, Capacity: 200, Active: true},
	}

	lb := NewLoadBalancer(nodes)
	lb.DistributeLoad(300)
	lb.AddNode(Node{ID: "Node4", Load: 0, Capacity: 100, Active: true})
	lb.RemoveNode("Node2")
	lb.DistributeLoad(200)

	fmt.Println("Load history for Node1:", lb.GetLoadHistory("Node1"))
}
