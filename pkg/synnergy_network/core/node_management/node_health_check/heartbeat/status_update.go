package heartbeat

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

// Node represents a node in the blockchain network.
type Node struct {
	ID          string    `json:"id"`
	Address     string    `json:"address"`
	Status      string    `json:"status"`
	CPUUsage    float64   `json:"cpu_usage"`
	MemoryUsage float64   `json:"memory_usage"`
	DiskUsage   float64   `json:"disk_usage"`
	Latency     float64   `json:"latency"`
	LastUpdated time.Time `json:"last_updated"`
}

// StatusUpdate manages the status updates of nodes in the blockchain network.
type StatusUpdate struct {
	nodes map[string]*Node
	mu    sync.Mutex
}

// NewStatusUpdate creates a new StatusUpdate instance.
func NewStatusUpdate() *StatusUpdate {
	return &StatusUpdate{
		nodes: make(map[string]*Node),
	}
}

// RegisterNode registers a new node in the status update mechanism.
func (su *StatusUpdate) RegisterNode(id, address string) {
	su.mu.Lock()
	defer su.mu.Unlock()
	su.nodes[id] = &Node{
		ID:      id,
		Address: address,
		Status:  "unknown",
	}
}

// UpdateNodeStatus updates the status and performance metrics of a node.
func (su *StatusUpdate) UpdateNodeStatus(id, status string, cpuUsage, memoryUsage, diskUsage, latency float64) error {
	su.mu.Lock()
	defer su.mu.Unlock()
	node, exists := su.nodes[id]
	if !exists {
		return errors.New("node not found")
	}
	node.Status = status
	node.CPUUsage = cpuUsage
	node.MemoryUsage = memoryUsage
	node.DiskUsage = diskUsage
	node.Latency = latency
	node.LastUpdated = time.Now()
	return nil
}

// GetNodeStatus returns the status of a specific node.
func (su *StatusUpdate) GetNodeStatus(id string) (*Node, error) {
	su.mu.Lock()
	defer su.mu.Unlock()
	node, exists := su.nodes[id]
	if !exists {
		return nil, errors.New("node not found")
	}
	return node, nil
}

// GetAllNodeStatuses returns the statuses of all registered nodes.
func (su *StatusUpdate) GetAllNodeStatuses() map[string]*Node {
	su.mu.Lock()
	defer su.mu.Unlock()
	return su.nodes
}

// HandleStatusUpdate handles incoming status update requests.
func (su *StatusUpdate) HandleStatusUpdate(w http.ResponseWriter, r *http.Request) {
	var node Node
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err := su.UpdateNodeStatus(node.ID, node.Status, node.CPUUsage, node.MemoryUsage, node.DiskUsage, node.Latency)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ServeHTTP serves the HTTP requests for node status updates.
func (su *StatusUpdate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		su.HandleStatusUpdate(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// MonitorNodeStatus starts monitoring the status of nodes by sending periodic heartbeat signals.
func (su *StatusUpdate) MonitorNodeStatus(id string, interval time.Duration) {
	for {
		node, err := su.GetNodeStatus(id)
		if err != nil {
			return
		}

		resp, err := http.Get("http://" + node.Address + "/health")
		if err != nil {
			su.UpdateNodeStatus(id, "unreachable", 0, 0, 0, 0)
		} else {
			defer resp.Body.Close()
			var status Node
			if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
				su.UpdateNodeStatus(id, "unreachable", 0, 0, 0, 0)
			} else {
				su.UpdateNodeStatus(id, "healthy", status.CPUUsage, status.MemoryUsage, status.DiskUsage, status.Latency)
			}
		}
		time.Sleep(interval)
	}
}
