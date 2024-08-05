// Package simulation_tools contains tools for simulating various network scenarios.
package simulation_tools

import (
    "fmt"
    "time"
    "sync"
)

// Node represents a network node in the simulation.
type Node struct {
    ID            string
    IsAvailable   bool
    LastChecked   time.Time
}

// NetworkSimulation represents the simulation of network availability.
type NetworkSimulation struct {
    Nodes       []*Node
    Mutex       sync.Mutex
    Duration    time.Duration
    CheckInterval time.Duration
}

// NewNode creates a new Node with a given ID.
func NewNode(id string) *Node {
    return &Node{
        ID:          id,
        IsAvailable: true,
        LastChecked: time.Now(),
    }
}

// NewNetworkSimulation creates a new NetworkSimulation instance.
func NewNetworkSimulation(duration, checkInterval time.Duration) *NetworkSimulation {
    return &NetworkSimulation{
        Nodes:       []*Node{},
        Duration:    duration,
        CheckInterval: checkInterval,
    }
}

// AddNode adds a new node to the network simulation.
func (ns *NetworkSimulation) AddNode(node *Node) {
    ns.Mutex.Lock()
    defer ns.Mutex.Unlock()
    ns.Nodes = append(ns.Nodes, node)
}

// SimulateNodeAvailability simulates the availability of a single node.
func (ns *NetworkSimulation) SimulateNodeAvailability(node *Node) {
    ns.Mutex.Lock()
    defer ns.Mutex.Unlock()
    
    // Simulate node availability randomly for demo purposes.
    // In a real-world scenario, this would be based on more complex logic.
    node.IsAvailable = time.Now().UnixNano()%2 == 0
    node.LastChecked = time.Now()
}

// Start initiates the network availability simulation.
func (ns *NetworkSimulation) Start() {
    fmt.Println("Starting network availability simulation...")
    ticker := time.NewTicker(ns.CheckInterval)
    end := time.Now().Add(ns.Duration)
    
    for now := range ticker.C {
        if now.After(end) {
            ticker.Stop()
            break
        }
        for _, node := range ns.Nodes {
            ns.SimulateNodeAvailability(node)
            fmt.Printf("Node %s availability: %t\n", node.ID, node.IsAvailable)
        }
    }
    fmt.Println("Network availability simulation completed.")
}

// GetNodeStatus retrieves the current status of a node by ID.
func (ns *NetworkSimulation) GetNodeStatus(nodeID string) (bool, error) {
    ns.Mutex.Lock()
    defer ns.Mutex.Unlock()
    
    for _, node := range ns.Nodes {
        if node.ID == nodeID {
            return node.IsAvailable, nil
        }
    }
    return false, fmt.Errorf("node with ID %s not found", nodeID)
}

// GenerateReport generates a report of the simulation results.
func (ns *NetworkSimulation) GenerateReport() {
    ns.Mutex.Lock()
    defer ns.Mutex.Unlock()
    
    fmt.Println("Generating network availability report...")
    for _, node := range ns.Nodes {
        fmt.Printf("Node %s - Last Checked: %s - Availability: %t\n", node.ID, node.LastChecked, node.IsAvailable)
    }
}

func main() {
    simulationDuration := 1 * time.Minute
    checkInterval := 10 * time.Second
    ns := NewNetworkSimulation(simulationDuration, checkInterval)
    
    ns.AddNode(NewNode("Node1"))
    ns.AddNode(NewNode("Node2"))
    ns.AddNode(NewNode("Node3"))
    
    go ns.Start()
    
    // Wait for the simulation to complete
    time.Sleep(simulationDuration + checkInterval)
    
    ns.GenerateReport()
}
