package performance_metrics

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

// NodeMetrics represents the performance metrics of a node.
type NodeMetrics struct {
	ID          string    `json:"id"`
	CPUUsage    float64   `json:"cpu_usage"`
	MemoryUsage float64   `json:"memory_usage"`
	DiskUsage   float64   `json:"disk_usage"`
	Latency     float64   `json:"latency"`
	LastUpdated time.Time `json:"last_updated"`
}

// SystemInsightsManager manages the collection and analysis of performance metrics for nodes.
type SystemInsightsManager struct {
	nodes    map[string]*NodeMetrics
	mu       sync.Mutex
	interval time.Duration
}

// NewSystemInsightsManager creates a new SystemInsightsManager instance.
func NewSystemInsightsManager(interval time.Duration) *SystemInsightsManager {
	return &SystemInsightsManager{
		nodes:    make(map[string]*NodeMetrics),
		interval: interval,
	}
}

// RegisterNode registers a new node in the system insights manager.
func (sim *SystemInsightsManager) RegisterNode(id string) {
	sim.mu.Lock()
	defer sim.mu.Unlock()
	sim.nodes[id] = &NodeMetrics{
		ID: id,
	}
}

// UpdateNodeMetrics updates the metrics of a node.
func (sim *SystemInsightsManager) UpdateNodeMetrics(id string, cpuUsage, memoryUsage, diskUsage, latency float64) error {
	sim.mu.Lock()
	defer sim.mu.Unlock()
	node, exists := sim.nodes[id]
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

// GetNodeMetrics returns the metrics of a specific node.
func (sim *SystemInsightsManager) GetNodeMetrics(id string) (*NodeMetrics, error) {
	sim.mu.Lock()
	defer sim.mu.Unlock()
	node, exists := sim.nodes[id]
	if !exists {
		return nil, errors.New("node not found")
	}
	return node, nil
}

// GetAllNodeMetrics returns the metrics of all registered nodes.
func (sim *SystemInsightsManager) GetAllNodeMetrics() map[string]*NodeMetrics {
	sim.mu.Lock()
	defer sim.mu.Unlock()
	return sim.nodes
}

// HandleMetricsUpdate handles incoming metrics update requests.
func (sim *SystemInsightsManager) HandleMetricsUpdate(w http.ResponseWriter, r *http.Request) {
	var metrics NodeMetrics
	if err := json.NewDecoder(r.Body).Decode(&metrics); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err := sim.UpdateNodeMetrics(metrics.ID, metrics.CPUUsage, metrics.MemoryUsage, metrics.DiskUsage, metrics.Latency)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ServeHTTP serves the HTTP requests for metrics updates.
func (sim *SystemInsightsManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		sim.HandleMetricsUpdate(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// MonitorNodes starts monitoring the nodes for performance metrics by sending periodic requests.
func (sim *SystemInsightsManager) MonitorNodes() {
	for {
		sim.mu.Lock()
		for id, node := range sim.nodes {
			go func(id string, node *NodeMetrics) {
				resp, err := http.Get("http://" + node.ID + "/metrics")
				if err != nil {
					return
				}
				defer resp.Body.Close()
				var metrics NodeMetrics
				if err := json.NewDecoder(resp.Body).Decode(&metrics); err != nil {
					return
				}
				sim.UpdateNodeMetrics(id, metrics.CPUUsage, metrics.MemoryUsage, metrics.DiskUsage, metrics.Latency)
			}(id, node)
		}
		sim.mu.Unlock()
		time.Sleep(sim.interval)
	}
}

// Helper function to create an HTTP client with a timeout
func createHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
	}
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

// Real-time Alerting
func (sim *SystemInsightsManager) AlertOnThresholdExceed(cpuThreshold, memoryThreshold, diskThreshold, latencyThreshold float64) {
	for {
		sim.mu.Lock()
		for id, node := range sim.nodes {
			if node.CPUUsage > cpuThreshold || node.MemoryUsage > memoryThreshold || node.DiskUsage > diskThreshold || node.Latency > latencyThreshold {
				// Trigger alert logic here, e.g., send notification, log alert, etc.
				alertMessage := "Alert for node " + id + ": "
				if node.CPUUsage > cpuThreshold {
					alertMessage += "CPU usage high. "
				}
				if node.MemoryUsage > memoryThreshold {
					alertMessage += "Memory usage high. "
				}
				if node.DiskUsage > diskThreshold {
					alertMessage += "Disk usage high. "
				}
				if node.Latency > latencyThreshold {
					alertMessage += "Latency high. "
				}
				go sendAlert(alertMessage)
			}
		}
		sim.mu.Unlock()
		time.Sleep(sim.interval)
	}
}

// Dummy function to send alerts (to be implemented)
func sendAlert(message string) {
	// Implement alert sending logic here (e.g., send email, push notification, etc.)
}

