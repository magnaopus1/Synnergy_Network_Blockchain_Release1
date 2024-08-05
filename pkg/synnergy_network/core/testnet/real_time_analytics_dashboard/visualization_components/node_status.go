package visualizationcomponents

import (
    "encoding/json"
    "fmt"
    "net/http"
    "sync"
    "time"
)

// NodeStatus represents the status of a network node
type NodeStatus struct {
    NodeID       string    `json:"node_id"`
    Status       string    `json:"status"`       // e.g., active, inactive, syncing
    LastPingTime time.Time `json:"last_ping_time"`
    CPUUsage     float64   `json:"cpu_usage"`
    MemoryUsage  float64   `json:"memory_usage"`
    DiskUsage    float64   `json:"disk_usage"`
    NetworkIn    float64   `json:"network_in"`
    NetworkOut   float64   `json:"network_out"`
}

// NodeStatusManager manages the status of network nodes
type NodeStatusManager struct {
    Nodes map[string]NodeStatus
    Mutex sync.RWMutex
}

// InitializeManager initializes a new NodeStatusManager
func (nsm *NodeStatusManager) InitializeManager() {
    nsm.Nodes = make(map[string]NodeStatus)
}

// UpdateNodeStatus updates the status of a specific node
func (nsm *NodeStatusManager) UpdateNodeStatus(node NodeStatus) {
    nsm.Mutex.Lock()
    defer nsm.Mutex.Unlock()
    nsm.Nodes[node.NodeID] = node
}

// RemoveNode removes a node from the manager
func (nsm *NodeStatusManager) RemoveNode(nodeID string) {
    nsm.Mutex.Lock()
    defer nsm.Mutex.Unlock()
    delete(nsm.Nodes, nodeID)
}

// GetNodeStatus retrieves the status of a specific node
func (nsm *NodeStatusManager) GetNodeStatus(nodeID string) (NodeStatus, error) {
    nsm.Mutex.RLock()
    defer nsm.Mutex.RUnlock()
    if node, exists := nsm.Nodes[nodeID]; exists {
        return node, nil
    }
    return NodeStatus{}, fmt.Errorf("node with ID %s not found", nodeID)
}

// GetAllNodesStatus retrieves the status of all nodes
func (nsm *NodeStatusManager) GetAllNodesStatus() []NodeStatus {
    nsm.Mutex.RLock()
    defer nsm.Mutex.RUnlock()
    nodes := []NodeStatus{}
    for _, node := range nsm.Nodes {
        nodes = append(nodes, node)
    }
    return nodes
}

// ServeHTTP serves the node statuses over HTTP
func (nsm *NodeStatusManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    switch r.Method {
    case http.MethodGet:
        nsm.Mutex.RLock()
        defer nsm.Mutex.RUnlock()
        json.NewEncoder(w).Encode(nsm.GetAllNodesStatus())
    case http.MethodPost:
        var node NodeStatus
        if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        nsm.UpdateNodeStatus(node)
        w.WriteHeader(http.StatusCreated)
    case http.MethodDelete:
        var req struct {
            NodeID string `json:"node_id"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        nsm.RemoveNode(req.NodeID)
        w.WriteHeader(http.StatusOK)
    default:
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}

// Secure serves the node statuses over HTTPS
func (nsm *NodeStatusManager) Secure(certFile, keyFile string) error {
    srv := &http.Server{
        Addr:         ":443",
        Handler:      nsm,
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 10 * time.Second,
        IdleTimeout:  120 * time.Second,
    }
    return srv.ListenAndServeTLS(certFile, keyFile)
}

// Example usage for integration purposes
func integrateNodeStatusManager() {
    manager := &NodeStatusManager{}
    manager.InitializeManager()
    
    http.Handle("/node_status", manager)
    go func() {
        fmt.Println("Serving node status on http://localhost:8080")
        if err := http.ListenAndServe(":8080", nil); err != nil {
            fmt.Println("Failed to start HTTP server:", err)
        }
    }()
    
    fmt.Println("Serving secure node status on https://localhost")
    if err := manager.Secure("server.crt", "server.key"); err != nil {
        fmt.Println("Failed to start HTTPS server:", err)
    }
}
