// Package node provides functionalities and services for the nodes within the Synnergy Network blockchain,
// ensuring high-level performance, security, and real-world applicability. This redundancy_protocols.go file
// implements the logic for redundancy protocols within the network.

package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// NodeStatus represents the status of a node.
type NodeStatus struct {
	NodeID       string    `json:"node_id"`
	IsActive     bool      `json:"is_active"`
	LastChecked  time.Time `json:"last_checked"`
	ResponseTime float64   `json:"response_time"`
}

// RedundancyProtocol manages the redundancy protocols within the network.
type RedundancyProtocol struct {
	mu      sync.Mutex
	nodes   map[string]NodeStatus
	primary string
}

// NewRedundancyProtocol creates a new instance of RedundancyProtocol.
func NewRedundancyProtocol() *RedundancyProtocol {
	return &RedundancyProtocol{
		nodes: make(map[string]NodeStatus),
	}
}

// RegisterNode registers a new node in the redundancy protocol.
func (rp *RedundancyProtocol) RegisterNode(nodeID string) error {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	if _, exists := rp.nodes[nodeID]; exists {
		return errors.New("node already registered")
	}

	rp.nodes[nodeID] = NodeStatus{
		NodeID:       nodeID,
		IsActive:     true,
		LastChecked:  time.Now(),
		ResponseTime: 0.0,
	}

	if rp.primary == "" {
		rp.primary = nodeID
		log.Printf("Node %s set as primary", nodeID)
	}

	log.Printf("Node %s registered", nodeID)
	return nil
}

// UnregisterNode unregisters a node from the redundancy protocol.
func (rp *RedundancyProtocol) UnregisterNode(nodeID string) error {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	if _, exists := rp.nodes[nodeID]; !exists {
		return errors.New("node not found")
	}

	delete(rp.nodes, nodeID)
	if rp.primary == nodeID {
		rp.electNewPrimary()
	}

	log.Printf("Node %s unregistered", nodeID)
	return nil
}

// electNewPrimary elects a new primary node from the registered nodes.
func (rp *RedundancyProtocol) electNewPrimary() {
	var newPrimary string
	for nodeID := range rp.nodes {
		newPrimary = nodeID
		break
	}

	if newPrimary != "" {
		rp.primary = newPrimary
		log.Printf("Node %s elected as new primary", newPrimary)
	} else {
		rp.primary = ""
		log.Println("No nodes available to elect as primary")
	}
}

// MonitorNodes checks the status of all registered nodes and updates their status.
func (rp *RedundancyProtocol) MonitorNodes() {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	for nodeID, status := range rp.nodes {
		// Simulate checking the node status and response time
		status.IsActive = true
		status.ResponseTime = 100.0 // Simulate response time in milliseconds
		status.LastChecked = time.Now()
		rp.nodes[nodeID] = status
	}
}

// GetNodeStatus retrieves the status of a specific node.
func (rp *RedundancyProtocol) GetNodeStatus(nodeID string) (NodeStatus, error) {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	status, exists := rp.nodes[nodeID]
	if !exists {
		return NodeStatus{}, errors.New("node not found")
	}

	return status, nil
}

// GetPrimaryNode retrieves the current primary node.
func (rp *RedundancyProtocol) GetPrimaryNode() (string, error) {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	if rp.primary == "" {
		return "", errors.New("no primary node elected")
	}

	return rp.primary, nil
}

// ServeHTTP handles HTTP requests for the redundancy protocol status.
func (rp *RedundancyProtocol) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	statuses := make([]NodeStatus, 0, len(rp.nodes))
	for _, status := range rp.nodes {
		statuses = append(statuses, status)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(statuses); err != nil {
		http.Error(w, "Failed to encode node statuses", http.StatusInternalServerError)
		return
	}
}

// StartRedundancyServer starts an HTTP server for serving redundancy protocol status.
func StartRedundancyServer(port string, rp *RedundancyProtocol) {
	http.Handle("/redundancy", rp)
	log.Printf("Starting redundancy server on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start redundancy server: %v", err)
	}
}

// Example usage of redundancy protocol within the node package
func main() {
	redundancyProtocol := NewRedundancyProtocol()
	go StartRedundancyServer("8081", redundancyProtocol)

	// Simulate registering nodes
	redundancyProtocol.RegisterNode("node-1")
	redundancyProtocol.RegisterNode("node-2")

	// Simulate monitoring nodes
	for {
		redundancyProtocol.MonitorNodes()
		time.Sleep(5 * time.Second)
	}
}
