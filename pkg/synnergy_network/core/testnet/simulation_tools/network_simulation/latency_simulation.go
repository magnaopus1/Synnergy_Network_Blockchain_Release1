// Package network_simulation provides tools for simulating various network scenarios.
package network_simulation

import (
    "fmt"
    "math/rand"
    "sync"
    "time"
)

// Node represents a network node in the simulation.
type Node struct {
    ID              string
    Latency         time.Duration
    LastLatencyCheck time.Time
}

// LatencySimulation represents the simulation of network latency.
type LatencySimulation struct {
    Nodes          []*Node
    Mutex          sync.Mutex
    Duration       time.Duration
    CheckInterval  time.Duration
    LatencyChanges map[string][]time.Duration
}

// NewNode creates a new Node with a given ID.
func NewNode(id string) *Node {
    return &Node{
        ID:              id,
        Latency:         0,
        LastLatencyCheck: time.Now(),
    }
}

// NewLatencySimulation creates a new LatencySimulation instance.
func NewLatencySimulation(duration, checkInterval time.Duration) *LatencySimulation {
    return &LatencySimulation{
        Nodes:          []*Node{},
        Duration:       duration,
        CheckInterval:  checkInterval,
        LatencyChanges: make(map[string][]time.Duration),
    }
}

// AddNode adds a new node to the latency simulation.
func (ls *LatencySimulation) AddNode(node *Node) {
    ls.Mutex.Lock()
    defer ls.Mutex.Unlock()
    ls.Nodes = append(ls.Nodes, node)
}

// SimulateNodeLatency simulates the latency for a single node.
func (ls *LatencySimulation) SimulateNodeLatency(node *Node) {
    ls.Mutex.Lock()
    defer ls.Mutex.Unlock()

    // Simulate latency change randomly for demo purposes.
    // In a real-world scenario, this would be based on more complex logic.
    node.Latency = time.Duration(rand.Intn(100)) * time.Millisecond
    node.LastLatencyCheck = time.Now()
    ls.LatencyChanges[node.ID] = append(ls.LatencyChanges[node.ID], node.Latency)
}

// Start initiates the network latency simulation.
func (ls *LatencySimulation) Start() {
    fmt.Println("Starting network latency simulation...")
    ticker := time.NewTicker(ls.CheckInterval)
    end := time.Now().Add(ls.Duration)

    for now := range ticker.C {
        if now.After(end) {
            ticker.Stop()
            break
        }
        for _, node := range ls.Nodes {
            ls.SimulateNodeLatency(node)
            fmt.Printf("Node %s latency: %s\n", node.ID, node.Latency)
        }
    }
    fmt.Println("Network latency simulation completed.")
}

// GetNodeLatency retrieves the current latency of a node by ID.
func (ls *LatencySimulation) GetNodeLatency(nodeID string) (time.Duration, error) {
    ls.Mutex.Lock()
    defer ls.Mutex.Unlock()

    for _, node := range ls.Nodes {
        if node.ID == nodeID {
            return node.Latency, nil
        }
    }
    return 0, fmt.Errorf("node with ID %s not found", nodeID)
}

// GenerateReport generates a report of the simulation results.
func (ls *LatencySimulation) GenerateReport() {
    ls.Mutex.Lock()
    defer ls.Mutex.Unlock()

    fmt.Println("Generating network latency report...")
    for _, node := range ls.Nodes {
        fmt.Printf("Node %s - Last Checked: %s - Latency: %s\n", node.ID, node.LastLatencyCheck, node.Latency)
        fmt.Printf("Latency Changes for Node %s: %v\n", node.ID, ls.LatencyChanges[node.ID])
    }
}

// ExportLatencyData exports the latency data for all nodes.
func (ls *LatencySimulation) ExportLatencyData() map[string][]time.Duration {
    ls.Mutex.Lock()
    defer ls.Mutex.Unlock()

    data := make(map[string][]time.Duration)
    for id, changes := range ls.LatencyChanges {
        data[id] = changes
    }
    return data
}

// SaveReportToBlockchain saves the generated report to the blockchain for immutable record-keeping.
func (ls *LatencySimulation) SaveReportToBlockchain() {
    // Placeholder for blockchain integration
    fmt.Println("Saving report to blockchain... (not implemented)")
}

// AdvancedLatencyAnalysis performs an advanced analysis of the latency data.
func (ls *LatencySimulation) AdvancedLatencyAnalysis() {
    // Placeholder for advanced analysis logic
    fmt.Println("Performing advanced latency analysis... (not implemented)")
}
