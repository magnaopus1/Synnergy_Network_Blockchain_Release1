package health_api

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
	"runtime"
	"log"
)

// HealthStatus represents the health status of a node.
type HealthStatus struct {
	NodeID        string  `json:"node_id"`
	CPUUsage      float64 `json:"cpu_usage"`
	MemoryUsage   float64 `json:"memory_usage"`
	DiskUsage     float64 `json:"disk_usage"`
	NetworkLatency float64 `json:"network_latency"`
	Status        string  `json:"status"`
	LastUpdated   time.Time `json:"last_updated"`
}

// HealthAPI manages the health check API endpoint.
type HealthAPI struct {
	mu         sync.Mutex
	nodeID     string
	status     HealthStatus
	quarantine bool
}

// NewHealthAPI creates a new HealthAPI instance.
func NewHealthAPI(nodeID string) *HealthAPI {
	return &HealthAPI{
		nodeID: nodeID,
		status: HealthStatus{
			NodeID: nodeID,
			Status: "healthy",
		},
	}
}

// Start starts the health API server.
func (api *HealthAPI) Start(addr string) {
	http.HandleFunc("/health", api.handleHealthCheck)
	http.HandleFunc("/quarantine", api.handleQuarantine)
	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Fatalf("Failed to start health API server: %v", err)
		}
	}()
	go api.collectMetrics()
}

// handleHealthCheck handles the health check requests.
func (api *HealthAPI) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	api.mu.Lock()
	defer api.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(api.status)
}

// handleQuarantine handles requests to manually quarantine the node.
func (api *HealthAPI) handleQuarantine(w http.ResponseWriter, r *http.Request) {
	api.mu.Lock()
	defer api.mu.Unlock()

	api.quarantine = true
	api.status.Status = "quarantined"
	api.status.LastUpdated = time.Now()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Node has been quarantined"))
}

// collectMetrics periodically collects performance metrics.
func (api *HealthAPI) collectMetrics() {
	for {
		if api.quarantine {
			time.Sleep(10 * time.Second)
			continue
		}
		
		cpuUsage := api.getCPUUsage()
		memoryUsage := api.getMemoryUsage()
		diskUsage := api.getDiskUsage()
		networkLatency := api.getNetworkLatency()

		api.mu.Lock()
		api.status.CPUUsage = cpuUsage
		api.status.MemoryUsage = memoryUsage
		api.status.DiskUsage = diskUsage
		api.status.NetworkLatency = networkLatency
		api.status.LastUpdated = time.Now()

		if cpuUsage > 90 || memoryUsage > 90 || diskUsage > 90 {
			api.status.Status = "unhealthy"
		} else {
			api.status.Status = "healthy"
		}

		api.mu.Unlock()
		time.Sleep(10 * time.Second)
	}
}

// getCPUUsage collects the CPU usage.
func (api *HealthAPI) getCPUUsage() float64 {
	// Mock implementation. Replace with actual logic to get CPU usage.
	return float64(runtime.NumGoroutine()) / 10.0
}

// getMemoryUsage collects the memory usage.
func (api *HealthAPI) getMemoryUsage() float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.Alloc) / float64(m.TotalAlloc) * 100
}

// getDiskUsage collects the disk usage.
func (api *HealthAPI) getDiskUsage() float64 {
	// Mock implementation. Replace with actual logic to get Disk usage.
	return 50.0
}

// getNetworkLatency collects the network latency.
func (api *HealthAPI) getNetworkLatency() float64 {
	// Mock implementation. Replace with actual logic to measure network latency.
	return 10.0
}

