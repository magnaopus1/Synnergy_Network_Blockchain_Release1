package performance_metrics

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Metrics represents the performance metrics of a node.
type Metrics struct {
	ID          string    `json:"id"`
	CPUUsage    float64   `json:"cpu_usage"`
	MemoryUsage float64   `json:"memory_usage"`
	DiskUsage   float64   `json:"disk_usage"`
	Latency     float64   `json:"latency"`
	LastUpdated time.Time `json:"last_updated"`
}

// MetricsCollectionManager manages the collection of performance metrics for nodes.
type MetricsCollectionManager struct {
	nodes    map[string]*Metrics
	mu       sync.Mutex
	interval time.Duration
}

// NewMetricsCollectionManager creates a new MetricsCollectionManager instance.
func NewMetricsCollectionManager(interval time.Duration) *MetricsCollectionManager {
	return &MetricsCollectionManager{
		nodes:    make(map[string]*Metrics),
		interval: interval,
	}
}

// RegisterNode registers a new node in the metrics collection manager.
func (mcm *MetricsCollectionManager) RegisterNode(id string) {
	mcm.mu.Lock()
	defer mcm.mu.Unlock()
	mcm.nodes[id] = &Metrics{
		ID: id,
	}
}

// UpdateNodeMetrics updates the metrics of a node.
func (mcm *MetricsCollectionManager) UpdateNodeMetrics(id string, cpuUsage, memoryUsage, diskUsage, latency float64) error {
	mcm.mu.Lock()
	defer mcm.mu.Unlock()
	node, exists := mcm.nodes[id]
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
func (mcm *MetricsCollectionManager) GetNodeMetrics(id string) (*Metrics, error) {
	mcm.mu.Lock()
	defer mcm.mu.Unlock()
	node, exists := mcm.nodes[id]
	if !exists {
		return nil, errors.New("node not found")
	}
	return node, nil
}

// GetAllNodeMetrics returns the metrics of all registered nodes.
func (mcm *MetricsCollectionManager) GetAllNodeMetrics() map[string]*Metrics {
	mcm.mu.Lock()
	defer mcm.mu.Unlock()
	return mcm.nodes
}

// HandleMetricsUpdate handles incoming metrics update requests.
func (mcm *MetricsCollectionManager) HandleMetricsUpdate(w http.ResponseWriter, r *http.Request) {
	var metrics Metrics
	if err := json.NewDecoder(r.Body).Decode(&metrics); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err := mcm.UpdateNodeMetrics(metrics.ID, metrics.CPUUsage, metrics.MemoryUsage, metrics.DiskUsage, metrics.Latency)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ServeHTTP serves the HTTP requests for metrics updates.
func (mcm *MetricsCollectionManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		mcm.HandleMetricsUpdate(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// MonitorNodes starts monitoring the nodes for performance metrics by sending periodic requests.
func (mcm *MetricsCollectionManager) MonitorNodes() {
	for {
		mcm.mu.Lock()
		for id, node := range mcm.nodes {
			resp, err := http.Get("http://" + node.Address + "/metrics")
			if err != nil {
				continue
			}
			defer resp.Body.Close()
			var metrics Metrics
			if err := json.NewDecoder(resp.Body).Decode(&metrics); err != nil {
				continue
			}
			mcm.UpdateNodeMetrics(id, metrics.CPUUsage, metrics.MemoryUsage, metrics.DiskUsage, metrics.Latency)
		}
		mcm.mu.Unlock()
		time.Sleep(mcm.interval)
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
