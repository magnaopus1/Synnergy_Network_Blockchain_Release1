package bridge

import (
    "errors"
    "log"
    "sync"
    "time"
)

// RedundancyManager manages redundancy protocols for the bridge
type RedundancyManager struct {
    activeNodes  map[string]bool
    nodeLock     sync.RWMutex
    heartbeatInterval time.Duration
    heartbeatTimeout  time.Duration
}

// NewRedundancyManager creates a new RedundancyManager
func NewRedundancyManager(heartbeatInterval, heartbeatTimeout time.Duration) *RedundancyManager {
    return &RedundancyManager{
        activeNodes:  make(map[string]bool),
        heartbeatInterval: heartbeatInterval,
        heartbeatTimeout:  heartbeatTimeout,
    }
}

// RegisterNode registers a new node in the redundancy manager
func (rm *RedundancyManager) RegisterNode(nodeID string) error {
    rm.nodeLock.Lock()
    defer rm.nodeLock.Unlock()

    if _, exists := rm.activeNodes[nodeID]; exists {
        return errors.New("node already registered")
    }

    rm.activeNodes[nodeID] = true
    log.Printf("Node %s registered", nodeID)
    return nil
}

// UnregisterNode unregisters a node from the redundancy manager
func (rm *RedundancyManager) UnregisterNode(nodeID string) error {
    rm.nodeLock.Lock()
    defer rm.nodeLock.Unlock()

    if _, exists := rm.activeNodes[nodeID]; !exists {
        return errors.New("node not found")
    }

    delete(rm.activeNodes, nodeID)
    log.Printf("Node %s unregistered", nodeID)
    return nil
}

// MonitorHeartbeats monitors heartbeats from all nodes to ensure they are active
func (rm *RedundancyManager) MonitorHeartbeats() {
    ticker := time.NewTicker(rm.heartbeatInterval)
    defer ticker.Stop()

    for range ticker.C {
        rm.checkNodeHeartbeats()
    }
}

// checkNodeHeartbeats checks the heartbeats of all registered nodes
func (rm *RedundancyManager) checkNodeHeartbeats() {
    rm.nodeLock.RLock()
    defer rm.nodeLock.RUnlock()

    for nodeID := range rm.activeNodes {
        if !rm.pingNode(nodeID) {
            log.Printf("Node %s failed heartbeat check", nodeID)
            rm.handleNodeFailure(nodeID)
        }
    }
}

// pingNode simulates pinging a node to check if it is active (stub implementation)
func (rm *RedundancyManager) pingNode(nodeID string) bool {
    // Simulate a ping to the node. In a real implementation, this would involve network communication.
    // Here, we assume the node is always active for demonstration purposes.
    return true
}

// handleNodeFailure handles a node failure by unregistering it and taking appropriate action
func (rm *RedundancyManager) handleNodeFailure(nodeID string) {
    rm.nodeLock.Lock()
    defer rm.nodeLock.Unlock()

    delete(rm.activeNodes, nodeID)
    log.Printf("Node %s has been removed due to failure", nodeID)

    // Implement additional logic for handling node failure, such as redistributing tasks, alerting administrators, etc.
}

// Example usage demonstrating comprehensive functionality
func ExampleComprehensiveFunctionality() {
    // Create a new redundancy manager with a heartbeat interval of 10 seconds and timeout of 5 seconds
    rm := NewRedundancyManager(10*time.Second, 5*time.Second)

    // Register nodes
    rm.RegisterNode("node1")
    rm.RegisterNode("node2")

    // Start monitoring heartbeats in a separate goroutine
    go rm.MonitorHeartbeats()

    // Simulate node activity
    time.Sleep(30 * time.Second)

    // Unregister a node
    rm.UnregisterNode("node1")
}
