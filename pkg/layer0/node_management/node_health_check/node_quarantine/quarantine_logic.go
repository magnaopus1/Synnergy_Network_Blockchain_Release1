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

// QuarantineManager manages the quarantine logic for nodes exhibiting abnormal behavior.
type QuarantineManager struct {
	nodes       map[string]*Node
	mu          sync.Mutex
	thresholds  Thresholds
	quarantineDuration time.Duration
}

// Thresholds represents the performance metric thresholds for detecting abnormal behavior.
type Thresholds struct {
	CPUUsage    float64
	MemoryUsage float64
	DiskUsage   float64
	Latency     float64
}

// NewQuarantineManager creates a new QuarantineManager instance.
func NewQuarantineManager(thresholds Thresholds, quarantineDuration time.Duration) *QuarantineManager {
	return &QuarantineManager{
		nodes:       make(map[string]*Node),
		thresholds:  thresholds,
		quarantineDuration: quarantineDuration,
	}
}

// RegisterNode registers a new node in the quarantine manager.
func (qm *QuarantineManager) RegisterNode(id, address string) {
	qm.mu.Lock()
	defer qm.mu.Unlock()
	qm.nodes[id] = &Node{
		ID:      id,
		Address: address,
		Status:  "healthy",
	}
}

// UpdateNodeMetrics updates the metrics of a node and checks for abnormal behavior.
func (qm *QuarantineManager) UpdateNodeMetrics(id string, cpuUsage, memoryUsage, diskUsage, latency float64) error {
	qm.mu.Lock()
	defer qm.mu.Unlock()
	node, exists := qm.nodes[id]
	if !exists {
		return errors.New("node not found")
	}
	node.CPUUsage = cpuUsage
	node.MemoryUsage = memoryUsage
	node.DiskUsage = diskUsage
	node.Latency = latency
	node.LastUpdated = time.Now()
	node.Status = qm.detectAbnormalBehavior(node)
	return nil
}

// detectAbnormalBehavior detects if a node exhibits abnormal behavior based on predefined thresholds.
func (qm *QuarantineManager) detectAbnormalBehavior(node *Node) string {
	if node.CPUUsage > qm.thresholds.CPUUsage || node.MemoryUsage > qm.thresholds.MemoryUsage ||
		node.DiskUsage > qm.thresholds.DiskUsage || node.Latency > qm.thresholds.Latency {
		qm.quarantineNode(node.ID)
		return "quarantined"
	}
	return "healthy"
}

// quarantineNode quarantines a node exhibiting abnormal behavior.
func (qm *QuarantineManager) quarantineNode(id string) {
	node, exists := qm.nodes[id]
	if !exists {
		return
	}
	node.Status = "quarantined"
	node.LastUpdated = time.Now()

	// Schedule a task to lift the quarantine after the specified duration
	go func() {
		time.Sleep(qm.quarantineDuration)
		qm.liftQuarantine(id)
	}()
}

// liftQuarantine lifts the quarantine status of a node after the quarantine period has elapsed.
func (qm *QuarantineManager) liftQuarantine(id string) {
	qm.mu.Lock()
	defer qm.mu.Unlock()
	node, exists := qm.nodes[id]
	if !exists {
		return
	}
	node.Status = "healthy"
	node.LastUpdated = time.Now()
}

// GetNodeStatus returns the status of a specific node.
func (qm *QuarantineManager) GetNodeStatus(id string) (*Node, error) {
	qm.mu.Lock()
	defer qm.mu.Unlock()
	node, exists := qm.nodes[id]
	if !exists {
		return nil, errors.New("node not found")
	}
	return node, nil
}

// GetAllNodeStatuses returns the statuses of all registered nodes.
func (qm *QuarantineManager) GetAllNodeStatuses() map[string]*Node {
	qm.mu.Lock()
	defer qm.mu.Unlock()
	return qm.nodes
}

// HandleNodeMetricsUpdate handles incoming node metrics update requests.
func (qm *QuarantineManager) HandleNodeMetricsUpdate(w http.ResponseWriter, r *http.Request) {
	var node Node
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err := qm.UpdateNodeMetrics(node.ID, node.CPUUsage, node.MemoryUsage, node.DiskUsage, node.Latency)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ServeHTTP serves the HTTP requests for node metrics updates.
func (qm *QuarantineManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		qm.HandleNodeMetricsUpdate(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// MonitorNodes starts monitoring the nodes for abnormal behavior by sending periodic heartbeat signals.
func (qm *QuarantineManager) MonitorNodes(interval time.Duration) {
	for {
		qm.mu.Lock()
		for id, node := range qm.nodes {
			resp, err := http.Get("http://" + node.Address + "/health")
			if err != nil {
				qm.quarantineNode(id)
				continue
			}
			defer resp.Body.Close()
			var status Node
			if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
				qm.quarantineNode(id)
				continue
			}
			qm.UpdateNodeMetrics(id, status.CPUUsage, status.MemoryUsage, status.DiskUsage, status.Latency)
		}
		qm.mu.Unlock()
		time.Sleep(interval)
	}
}
