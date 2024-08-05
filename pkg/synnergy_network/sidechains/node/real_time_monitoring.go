// Package node provides functionalities and services for the nodes within the Synnergy Network blockchain,
// ensuring high-level performance, security, and real-world applicability. This real_time_monitoring.go file
// implements the logic for real-time monitoring of nodes within the network.

package node

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

// NodeMetrics stores the metrics for a single node.
type NodeMetrics struct {
	NodeID            string    `json:"node_id"`
	CPUUsage          float64   `json:"cpu_usage"`
	MemoryUsage       float64   `json:"memory_usage"`
	NetworkIn         float64   `json:"network_in"`
	NetworkOut        float64   `json:"network_out"`
	ActiveConnections int       `json:"active_connections"`
	LastUpdated       time.Time `json:"last_updated"`
}

// NodeMonitor is responsible for monitoring the real-time status of nodes.
type NodeMonitor struct {
	mu      sync.Mutex
	metrics map[string]NodeMetrics
}

// NewNodeMonitor creates a new instance of NodeMonitor.
func NewNodeMonitor() *NodeMonitor {
	return &NodeMonitor{
		metrics: make(map[string]NodeMetrics),
	}
}

// UpdateMetrics updates the metrics for a given node.
func (nm *NodeMonitor) UpdateMetrics(nodeID string, cpuUsage, memoryUsage, networkIn, networkOut float64, activeConnections int) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	nm.metrics[nodeID] = NodeMetrics{
		NodeID:            nodeID,
		CPUUsage:          cpuUsage,
		MemoryUsage:       memoryUsage,
		NetworkIn:         networkIn,
		NetworkOut:        networkOut,
		ActiveConnections: activeConnections,
		LastUpdated:       time.Now(),
	}
}

// GetMetrics retrieves the metrics for all nodes.
func (nm *NodeMonitor) GetMetrics() []NodeMetrics {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	metrics := make([]NodeMetrics, 0, len(nm.metrics))
	for _, metric := range nm.metrics {
		metrics = append(metrics, metric)
	}
	return metrics
}

// ServeHTTP handles HTTP requests for the real-time metrics.
func (nm *NodeMonitor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	metrics := nm.GetMetrics()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metrics); err != nil {
		http.Error(w, "Failed to encode metrics", http.StatusInternalServerError)
		return
	}
}

// StartMonitoringServer starts an HTTP server for serving real-time metrics.
func StartMonitoringServer(port string, nm *NodeMonitor) {
	http.Handle("/metrics", nm)
	log.Printf("Starting monitoring server on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start monitoring server: %v", err)
	}
}

// Example usage of real-time monitoring within the node package
func main() {
	nodeMonitor := NewNodeMonitor()
	go StartMonitoringServer("8080", nodeMonitor)

	// Simulate updating metrics
	for {
		nodeMonitor.UpdateMetrics("node-1", 30.5, 2048, 500, 600, 10)
		nodeMonitor.UpdateMetrics("node-2", 40.0, 4096, 1000, 1200, 15)
		time.Sleep(5 * time.Second)
	}
}
