package optimization

import (
	"log"
	"sync"
	"time"

	"github.com/synthron_blockchain/pkg/layer0/core/resource_management/models"
)

// Optimizer manages the optimization of resource allocation within the blockchain network.
type Optimizer struct {
	mutex             sync.Mutex
	resourceThreshold models.ResourceThreshold
	scalingPolicy     models.ScalingPolicy
	optimizationLog   []models.OptimizationRecord
	resourceMonitor   *ResourceMonitor
}

// NewOptimizer creates a new resource optimizer with specified configurations.
func NewOptimizer(threshold models.ResourceThreshold, policy models.ScalingPolicy, monitor *ResourceMonitor) *Optimizer {
	return &Optimizer{
		resourceThreshold: threshold,
		scalingPolicy:     policy,
		resourceMonitor:   monitor,
	}
}

// OptimizeResources continuously evaluates the resource usage and adjusts the allocation dynamically.
func (o *Optimizer) OptimizeResources() {
	log.Println("Starting resource optimization process")
	for {
		o.mutex.Lock()
		currentUsage := o.resourceMonitor.FetchCurrentUsage()
		needsOptimization := o.checkIfOptimizationNeeded(currentUsage)

		if needsOptimization {
			o.applyOptimization(currentUsage)
		}

		o.mutex.Unlock()
		time.Sleep(10 * time.Second) // Check every 10 seconds
	}
}

// checkIfOptimizationNeeded determines whether resource optimization is needed based on thresholds.
func (o *Optimizer) checkIfOptimizationNeeded(currentUsage models.ResourceUsage) bool {
	return currentUsage.CPUUsage > o.resourceThreshold.CPUThreshold ||
		currentUsage.MemoryUsage > o.resourceThreshold.MemoryThreshold ||
		currentUsage.NetworkUsage > o.resourceThreshold.NetworkThreshold
}

// applyOptimization adjusts resources based on the current usage and predefined scaling policies.
func (o *Optimizer) applyOptimization(currentUsage models.ResourceUsage) {
	log.Printf("Applying resource optimization: %+v", currentUsage)
	optimizationRecord := models.OptimizationRecord{
		Time:       time.Now(),
		ResourceUsage: currentUsage,
		AdjustmentMade: o.scalingPolicy.DetermineAdjustment(currentUsage),
	}

	o.optimizationLog = append(o.optimizationLog, optimizationRecord)
	// Implement actual scaling logic based on scalingPolicy here
}

// ResourceMonitor simulates a component that provides current resource usage.
type ResourceMonitor struct {
	// Simulate fetching real-time data from system or resource management layer
}

// FetchCurrentUsage fetches the current resource usage from the system or resource management layer.
func (rm *ResourceMonitor) FetchCurrentUsage() models.ResourceUsage {
	// This should interact with system-level APIs to fetch real-time data
	return models.ResourceUsage{
		CPUUsage:    65.0, // Example data, replace with real monitoring data
		MemoryUsage: 8000, // in MB
		NetworkUsage: 300, // in Mbps
	}
}

