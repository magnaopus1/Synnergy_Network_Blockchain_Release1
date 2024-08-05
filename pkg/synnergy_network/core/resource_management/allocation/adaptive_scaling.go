package allocation

import (
    "fmt"
    "sync"
    "time"
)

// ResourceMetrics represents the metrics for resource usage
type ResourceMetrics struct {
    CPUUsage     float64
    MemoryUsage  float64
    NetworkUsage float64
    Timestamp    time.Time
}

// ResourceAllocation represents the allocation of resources to a node
type ResourceAllocation struct {
    NodeID    string
    CPU       int
    Memory    int
    Bandwidth int
}

// ResourceManager manages the allocation of resources dynamically
type ResourceManager struct {
    Allocations map[string]ResourceAllocation
    Metrics     map[string][]ResourceMetrics
    mu          sync.Mutex
}

// NewResourceManager initializes a new ResourceManager
func NewResourceManager() *ResourceManager {
    return &ResourceManager{
        Allocations: make(map[string]ResourceAllocation),
        Metrics:     make(map[string][]ResourceMetrics),
    }
}

// MonitorResources continuously monitors and updates the metrics for each node
func (rm *ResourceManager) MonitorResources(nodeID string, stopChan chan bool) {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            rm.updateMetrics(nodeID)
        case <-stopChan:
            fmt.Printf("Stopping monitoring for node: %s\n", nodeID)
            return
        }
    }
}

// updateMetrics fetches and stores the latest metrics for a given node
func (rm *ResourceManager) updateMetrics(nodeID string) {
    // Simulated metrics fetch; replace with actual monitoring logic
    metrics := ResourceMetrics{
        CPUUsage:     getRandomFloat(0, 100),
        MemoryUsage:  getRandomFloat(0, 100),
        NetworkUsage: getRandomFloat(0, 100),
        Timestamp:    time.Now(),
    }

    rm.mu.Lock()
    rm.Metrics[nodeID] = append(rm.Metrics[nodeID], metrics)
    rm.mu.Unlock()
}

// AdaptiveScaling adjusts resource allocations based on real-time metrics
func (rm *ResourceManager) AdaptiveScaling() {
    rm.mu.Lock()
    defer rm.mu.Unlock()

    for nodeID, metrics := range rm.Metrics {
        // Implement adaptive scaling logic based on metrics
        lastMetrics := metrics[len(metrics)-1]
        allocation := rm.Allocations[nodeID]

        if lastMetrics.CPUUsage > 80 {
            allocation.CPU += 1 // Scale up CPU
        } else if lastMetrics.CPUUsage < 20 {
            allocation.CPU -= 1 // Scale down CPU
        }

        if lastMetrics.MemoryUsage > 80 {
            allocation.Memory += 512 // Scale up Memory
        } else if lastMetrics.MemoryUsage < 20 {
            allocation.Memory -= 512 // Scale down Memory
        }

        rm.Allocations[nodeID] = allocation
    }
}

// getRandomFloat generates a random float between min and max
func getRandomFloat(min, max float64) float64 {
    return min + rand.Float64()*(max-min)
}
