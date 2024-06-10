package node_health_check

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

// NodeHealth represents the health status and performance metrics of a node.
type NodeHealth struct {
	ID          string    `json:"id"`
	CPUUsage    float64   `json:"cpu_usage"`
	MemoryUsage float64   `json:"memory_usage"`
	DiskUsage   float64   `json:"disk_usage"`
	Latency     float64   `json:"latency"`
	LastUpdated time.Time `json:"last_updated"`
}

// HealthCheckManager manages the health check and monitoring of nodes.
type HealthCheckManager struct {
	nodes       map[string]*NodeHealth
	mu          sync.Mutex
	checkInterval time.Duration
	alertThresholds AlertThresholds
	quarantineManager *QuarantineManager
}

// AlertThresholds represents the thresholds for triggering alerts.
type AlertThresholds struct {
	CPUUsage    float64
	MemoryUsage float64
	DiskUsage   float64
	Latency     float64
}

// QuarantineManager handles node quarantine operations.
type QuarantineManager struct {
	quarantinedNodes map[string]bool
	mu               sync.Mutex
}

// NewHealthCheckManager creates a new HealthCheckManager instance.
func NewHealthCheckManager(interval time.Duration, thresholds AlertThresholds) *HealthCheckManager {
	return &HealthCheckManager{
		nodes:            make(map[string]*NodeHealth),
		checkInterval:    interval,
		alertThresholds:  thresholds,
		quarantineManager: NewQuarantineManager(),
	}
}

// NewQuarantineManager creates a new QuarantineManager instance.
func NewQuarantineManager() *QuarantineManager {
	return &QuarantineManager{
		quarantinedNodes: make(map[string]bool),
	}
}

// RegisterNode registers a new node in the health check manager.
func (hcm *HealthCheckManager) RegisterNode(id string) {
	hcm.mu.Lock()
	defer hcm.mu.Unlock()
	hcm.nodes[id] = &NodeHealth{
		ID: id,
	}
}

// UpdateNodeHealth updates the health metrics of a node.
func (hcm *HealthCheckManager) UpdateNodeHealth(id string, cpuUsage, memoryUsage, diskUsage, latency float64) error {
	hcm.mu.Lock()
	defer hcm.mu.Unlock()
	node, exists := hcm.nodes[id]
	if !exists {
		return errors.New("node not found")
	}
	node.CPUUsage = cpuUsage
	node.MemoryUsage = memoryUsage
	node.DiskUsage = diskUsage
	node.Latency = latency
	node.LastUpdated = time.Now()
	return nil
}

// GetNodeHealth returns the health metrics of a specific node.
func (hcm *HealthCheckManager) GetNodeHealth(id string) (*NodeHealth, error) {
	hcm.mu.Lock()
	defer hcm.mu.Unlock()
	node, exists := hcm.nodes[id]
	if !exists {
		return nil, errors.New("node not found")
	}
	return node, nil
}

// GetAllNodeHealth returns the health metrics of all registered nodes.
func (hcm *HealthCheckManager) GetAllNodeHealth() map[string]*NodeHealth {
	hcm.mu.Lock()
	defer hcm.mu.Unlock()
	return hcm.nodes
}

// HandleHealthUpdate handles incoming health update requests.
func (hcm *HealthCheckManager) HandleHealthUpdate(w http.ResponseWriter, r *http.Request) {
	var health NodeHealth
	if err := json.NewDecoder(r.Body).Decode(&health); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err := hcm.UpdateNodeHealth(health.ID, health.CPUUsage, health.MemoryUsage, health.DiskUsage, health.Latency)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ServeHTTP serves the HTTP requests for health updates.
func (hcm *HealthCheckManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		hcm.HandleHealthUpdate(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// MonitorNodes starts monitoring the nodes for health metrics by sending periodic requests.
func (hcm *HealthCheckManager) MonitorNodes() {
	for {
		hcm.mu.Lock()
		for id, node := range hcm.nodes {
			go func(id string, node *NodeHealth) {
				resp, err := http.Get("http://" + node.ID + "/metrics")
				if err != nil {
					return
				}
				defer resp.Body.Close()
				var health NodeHealth
				if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
					return
				}
				hcm.UpdateNodeHealth(id, health.CPUUsage, health.MemoryUsage, health.DiskUsage, health.Latency)
				hcm.CheckAndQuarantineNode(id, health)
			}(id, node)
		}
		hcm.mu.Unlock()
		time.Sleep(hcm.checkInterval)
	}
}

// CheckAndQuarantineNode checks node health against thresholds and quarantines if necessary.
func (hcm *HealthCheckManager) CheckAndQuarantineNode(id string, health NodeHealth) {
	if health.CPUUsage > hcm.alertThresholds.CPUUsage ||
		health.MemoryUsage > hcm.alertThresholds.MemoryUsage ||
		health.DiskUsage > hcm.alertThresholds.DiskUsage ||
		health.Latency > hcm.alertThresholds.Latency {
		hcm.quarantineManager.QuarantineNode(id)
		sendAlert("Node " + id + " exceeds health thresholds and has been quarantined.")
	}
}

// QuarantineNode quarantines a node.
func (qm *QuarantineManager) QuarantineNode(id string) {
	qm.mu.Lock()
	defer qm.mu.Unlock()
	qm.quarantinedNodes[id] = true
}

// IsNodeQuarantined checks if a node is quarantined.
func (qm *QuarantineManager) IsNodeQuarantined(id string) bool {
	qm.mu.Lock()
	defer qm.mu.Unlock()
	return qm.quarantinedNodes[id]
}

// Secure communication using TLS
func createSecureHTTPClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		// Add TLS configuration here
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

// Dummy function to send alerts (to be implemented)
func sendAlert(message string) {
	// Implement alert sending logic here (e.g., send email, push notification, etc.)
}
