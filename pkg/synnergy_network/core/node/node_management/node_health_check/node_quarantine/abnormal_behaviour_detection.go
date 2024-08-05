package node_quarantine

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

// AbnormalBehaviorDetection manages the detection of abnormal behaviors in nodes.
type AbnormalBehaviorDetection struct {
	nodes map[string]*Node
	mu    sync.Mutex
	thresholds Thresholds
}

// Thresholds represents the performance metric thresholds for detecting abnormal behavior.
type Thresholds struct {
	CPUUsage    float64
	MemoryUsage float64
	DiskUsage   float64
	Latency     float64
}

// NewAbnormalBehaviorDetection creates a new AbnormalBehaviorDetection instance.
func NewAbnormalBehaviorDetection(thresholds Thresholds) *AbnormalBehaviorDetection {
	return &AbnormalBehaviorDetection{
		nodes:      make(map[string]*Node),
		thresholds: thresholds,
	}
}

// RegisterNode registers a new node in the abnormal behavior detection system.
func (abd *AbnormalBehaviorDetection) RegisterNode(id, address string) {
	abd.mu.Lock()
	defer abd.mu.Unlock()
	abd.nodes[id] = &Node{
		ID:      id,
		Address: address,
		Status:  "healthy",
	}
}

// UpdateNodeMetrics updates the metrics of a node and checks for abnormal behavior.
func (abd *AbnormalBehaviorDetection) UpdateNodeMetrics(id string, cpuUsage, memoryUsage, diskUsage, latency float64) error {
	abd.mu.Lock()
	defer abd.mu.Unlock()
	node, exists := abd.nodes[id]
	if !exists {
		return errors.New("node not found")
	}
	node.CPUUsage = cpuUsage
	node.MemoryUsage = memoryUsage
	node.DiskUsage = diskUsage
	node.Latency = latency
	node.LastUpdated = time.Now()
	node.Status = abd.detectAbnormalBehavior(node)
	return nil
}

// detectAbnormalBehavior detects if a node exhibits abnormal behavior based on predefined thresholds.
func (abd *AbnormalBehaviorDetection) detectAbnormalBehavior(node *Node) string {
	if node.CPUUsage > abd.thresholds.CPUUsage || node.MemoryUsage > abd.thresholds.MemoryUsage ||
		node.DiskUsage > abd.thresholds.DiskUsage || node.Latency > abd.thresholds.Latency {
		return "quarantined"
	}
	return "healthy"
}

// GetNodeStatus returns the status of a specific node.
func (abd *AbnormalBehaviorDetection) GetNodeStatus(id string) (*Node, error) {
	abd.mu.Lock()
	defer abd.mu.Unlock()
	node, exists := abd.nodes[id]
	if !exists {
		return nil, errors.New("node not found")
	}
	return node, nil
}

// GetAllNodeStatuses returns the statuses of all registered nodes.
func (abd *AbnormalBehaviorDetection) GetAllNodeStatuses() map[string]*Node {
	abd.mu.Lock()
	defer abd.mu.Unlock()
	return abd.nodes
}

// HandleNodeMetricsUpdate handles incoming node metrics update requests.
func (abd *AbnormalBehaviorDetection) HandleNodeMetricsUpdate(w http.ResponseWriter, r *http.Request) {
	var node Node
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err := abd.UpdateNodeMetrics(node.ID, node.CPUUsage, node.MemoryUsage, node.DiskUsage, node.Latency)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ServeHTTP serves the HTTP requests for node metrics updates.
func (abd *AbnormalBehaviorDetection) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		abd.HandleNodeMetricsUpdate(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// MonitorNodes starts monitoring the nodes for abnormal behavior by sending periodic heartbeat signals.
func (abd *AbnormalBehaviorDetection) MonitorNodes(interval time.Duration) {
	for {
		abd.mu.Lock()
		for id, node := range abd.nodes {
			resp, err := http.Get("http://" + node.Address + "/health")
			if err != nil {
				abd.updateNodeStatusToQuarantined(id)
				continue
			}
			defer resp.Body.Close()
			var status Node
			if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
				abd.updateNodeStatusToQuarantined(id)
				continue
			}
			abd.UpdateNodeMetrics(id, status.CPUUsage, status.MemoryUsage, status.DiskUsage, status.Latency)
		}
		abd.mu.Unlock()
		time.Sleep(interval)
	}
}

// updateNodeStatusToQuarantined sets the status of a node to quarantined.
func (abd *AbnormalBehaviorDetection) updateNodeStatusToQuarantined(id string) {
	node, exists := abd.nodes[id]
	if !exists {
		return
	}
	node.Status = "quarantined"
	node.LastUpdated = time.Now()
}
