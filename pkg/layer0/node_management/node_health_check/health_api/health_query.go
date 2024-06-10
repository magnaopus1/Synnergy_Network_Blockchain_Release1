package health_api

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

// NodeHealthQuery is a structure to query and store health information of nodes.
type NodeHealthQuery struct {
	mu        sync.Mutex
	nodes     map[string]*HealthStatus
	apiClient *http.Client
}

// NewNodeHealthQuery creates a new NodeHealthQuery instance.
func NewNodeHealthQuery() *NodeHealthQuery {
	return &NodeHealthQuery{
		nodes:     make(map[string]*HealthStatus),
		apiClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// RegisterNode adds a new node to the health query system.
func (nhq *NodeHealthQuery) RegisterNode(nodeID string, url string) {
	nhq.mu.Lock()
	defer nhq.mu.Unlock()
	nhq.nodes[nodeID] = &HealthStatus{
		NodeID: nodeID,
		Status: "unknown",
	}
	go nhq.fetchHealthStatus(nodeID, url)
}

// fetchHealthStatus fetches the health status of a node from its health API endpoint.
func (nhq *NodeHealthQuery) fetchHealthStatus(nodeID string, url string) {
	for {
		resp, err := nhq.apiClient.Get(url + "/health")
		if err != nil {
			nhq.updateNodeStatus(nodeID, "unreachable", 0, 0, 0, 0)
		} else {
			defer resp.Body.Close()
			var status HealthStatus
			if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
				nhq.updateNodeStatus(nodeID, "unreachable", 0, 0, 0, 0)
			} else {
				nhq.updateNodeStatus(nodeID, status.Status, status.CPUUsage, status.MemoryUsage, status.DiskUsage, status.NetworkLatency)
			}
		}
		time.Sleep(10 * time.Second)
	}
}

// updateNodeStatus updates the health status of a node.
func (nhq *NodeHealthQuery) updateNodeStatus(nodeID string, status string, cpuUsage, memoryUsage, diskUsage, networkLatency float64) {
	nhq.mu.Lock()
	defer nhq.mu.Unlock()
	nodeStatus, exists := nhq.nodes[nodeID]
	if exists {
		nodeStatus.Status = status
		nodeStatus.CPUUsage = cpuUsage
		nodeStatus.MemoryUsage = memoryUsage
		nodeStatus.DiskUsage = diskUsage
		nodeStatus.NetworkLatency = networkLatency
		nodeStatus.LastUpdated = time.Now()
	}
}

// GetNodeStatus returns the health status of a node.
func (nhq *NodeHealthQuery) GetNodeStatus(nodeID string) (*HealthStatus, error) {
	nhq.mu.Lock()
	defer nhq.mu.Unlock()
	nodeStatus, exists := nhq.nodes[nodeID]
	if !exists {
		return nil, errors.New("node not found")
	}
	return nodeStatus, nil
}

// GetAllNodeStatuses returns the health statuses of all nodes.
func (nhq *NodeHealthQuery) GetAllNodeStatuses() map[string]*HealthStatus {
	nhq.mu.Lock()
	defer nhq.mu.Unlock()
	return nhq.nodes
}
