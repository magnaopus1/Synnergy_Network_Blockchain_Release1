package heartbeat

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Node represents a node in the blockchain network.
type Node struct {
	ID          string  `json:"id"`
	Address     string  `json:"address"`
	Status      string  `json:"status"`
	CPUUsage    float64 `json:"cpu_usage"`
	MemoryUsage float64 `json:"memory_usage"`
	DiskUsage   float64 `json:"disk_usage"`
	Latency     float64 `json:"latency"`
	LastUpdated time.Time `json:"last_updated"`
}

// HeartbeatMechanism manages the heartbeat signals between nodes.
type HeartbeatMechanism struct {
	nodes map[string]*Node
	mu    sync.Mutex
	client *http.Client
}

// NewHeartbeatMechanism creates a new HeartbeatMechanism instance.
func NewHeartbeatMechanism() *HeartbeatMechanism {
	return &HeartbeatMechanism{
		nodes:  make(map[string]*Node),
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// RegisterNode registers a new node to the heartbeat mechanism.
func (hb *HeartbeatMechanism) RegisterNode(id, address string) {
	hb.mu.Lock()
	defer hb.mu.Unlock()
	hb.nodes[id] = &Node{
		ID:      id,
		Address: address,
		Status:  "unknown",
	}
	go hb.startHeartbeat(id)
}

// startHeartbeat starts sending heartbeat signals to the registered node.
func (hb *HeartbeatMechanism) startHeartbeat(id string) {
	for {
		hb.mu.Lock()
		node, exists := hb.nodes[id]
		hb.mu.Unlock()
		if !exists {
			return
		}

		resp, err := hb.client.Get(fmt.Sprintf("http://%s/health", node.Address))
		if err != nil {
			hb.updateNodeStatus(id, "unreachable", 0, 0, 0, 0)
		} else {
			defer resp.Body.Close()
			var status Node
			if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
				hb.updateNodeStatus(id, "unreachable", 0, 0, 0, 0)
			} else {
				hb.updateNodeStatus(id, "healthy", status.CPUUsage, status.MemoryUsage, status.DiskUsage, status.Latency)
			}
		}
		time.Sleep(10 * time.Second)
	}
}

// updateNodeStatus updates the status of a node.
func (hb *HeartbeatMechanism) updateNodeStatus(id, status string, cpuUsage, memoryUsage, diskUsage, latency float64) {
	hb.mu.Lock()
	defer hb.mu.Unlock()
	node, exists := hb.nodes[id]
	if exists {
		node.Status = status
		node.CPUUsage = cpuUsage
		node.MemoryUsage = memoryUsage
		node.DiskUsage = diskUsage
		node.Latency = latency
		node.LastUpdated = time.Now()
	}
}

// GetNodeStatus returns the status of a specific node.
func (hb *HeartbeatMechanism) GetNodeStatus(id string) (*Node, error) {
	hb.mu.Lock()
	defer hb.mu.Unlock()
	node, exists := hb.nodes[id]
	if !exists {
		return nil, fmt.Errorf("node not found")
	}
	return node, nil
}

// GetAllNodeStatuses returns the statuses of all registered nodes.
func (hb *HeartbeatMechanism) GetAllNodeStatuses() map[string]*Node {
	hb.mu.Lock()
	defer hb.mu.Unlock()
	return hb.nodes
}

// QuarantineNode quarantines a node exhibiting abnormal behavior or performance degradation.
func (hb *HeartbeatMechanism) QuarantineNode(id string) error {
	hb.mu.Lock()
	defer hb.mu.Unlock()
	node, exists := hb.nodes[id]
	if !exists {
		return fmt.Errorf("node not found")
	}
	node.Status = "quarantined"
	return nil
}

// CollectPerformanceMetrics extends the heartbeat mechanism to collect additional performance metrics.
func (hb *HeartbeatMechanism) CollectPerformanceMetrics(id string) (map[string]float64, error) {
	hb.mu.Lock()
	defer hb.mu.Unlock()
	node, exists := hb.nodes[id]
	if !exists {
		return nil, fmt.Errorf("node not found")
	}
	metrics := map[string]float64{
		"cpu_usage":    node.CPUUsage,
		"memory_usage": node.MemoryUsage,
		"disk_usage":   node.DiskUsage,
		"latency":      node.Latency,
	}
	return metrics, nil
}
