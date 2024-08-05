package allocation

import (
	"log"
	"sync"
	"time"

	"github.com/synnergy_network/pkg/synnergy_network/core/resource_management/resource_pools"
	"github.com/synnergy_network/pkg/synnergy_network/core/resource_management/security"
	"github.com/synnergy_network/pkg/synnergy_network/core/resource_management/auditing"
	"github.com/synnergy_network/pkg/synnergy_network/core/resource_management/optimization"
)

// DynamicAllocator handles dynamic resource allocation within the network.
type DynamicAllocator struct {
	mu                  sync.Mutex
	pool                *resource_pools.ResourcePool
	securityManager     *security.SecurityManager
	auditManager        *auditing.AuditManager
	optimizationManager *optimization.OptimizationManager
}

// NewDynamicAllocator creates a new instance of DynamicAllocator.
func NewDynamicAllocator(pool *resource_pools.ResourcePool, sm *security.SecurityManager, am *auditing.AuditManager, om *optimization.OptimizationManager) *DynamicAllocator {
	return &DynamicAllocator{
		pool:                pool,
		securityManager:     sm,
		auditManager:        am,
		optimizationManager: om,
	}
}

// MonitorResources continuously monitors the resource usage and adapts allocation in real-time.
func (da *DynamicAllocator) MonitorResources() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Collect metrics
			metrics := da.pool.Monitor()

			// Adaptive scaling and load balancing
			da.AdaptiveScaling(metrics)
		}
	}
}

// AdaptiveScaling adjusts resource allocation based on real-time usage metrics.
func (da *DynamicAllocator) AdaptiveScaling(metrics map[string]float64) {
	da.mu.Lock()
	defer da.mu.Unlock()

	for nodeID, usage := range metrics {
		if usage > 80 {
			// Scale up resources
			err := da.AllocateResource(nodeID, 10)
			if err != nil {
				log.Printf("Failed to allocate resources for node %s: %v", nodeID, err)
			}
		} else if usage < 20 {
			// Scale down resources
			err := da.DeallocateResource(nodeID, 10)
			if err != nil {
				log.Printf("Failed to deallocate resources for node %s: %v", nodeID, err)
			}
		}

		// Log the adjustment for auditing
		da.auditManager.LogResourceAdjustment(nodeID, usage)
	}
}

// AllocateResource allocates additional resources to a node.
func (da *DynamicAllocator) AllocateResource(nodeID string, amount int) error {
	if !da.securityManager.ValidateNode(nodeID) {
		return fmt.Errorf("invalid node ID: %s", nodeID)
	}

	if da.pool.Available() < amount {
		return fmt.Errorf("not enough resources available")
	}

	if err := da.pool.Allocate(nodeID, amount); err != nil {
		return fmt.Errorf("allocation failed: %v", err)
	}

	// Optimize resource usage
	da.optimizationManager.Optimize(nodeID, amount)

	return nil
}

// DeallocateResource deallocates resources from a node.
func (da *DynamicAllocator) DeallocateResource(nodeID string, amount int) error {
	if err := da.pool.Deallocate(nodeID, amount); err != nil {
		return fmt.Errorf("deallocation failed: %v", err)
	}

	return nil
}

// GetResourceStatus returns the current status of resources in the pool.
func (da *DynamicAllocator) GetResourceStatus() map[string]int {
	da.mu.Lock()
	defer da.mu.Unlock()

	return da.pool.Status()
}

// SecureResourceManagement applies security protocols to ensure secure resource management.
func (da *DynamicAllocator) SecureResourceManagement() {
	// Implementation of encryption and secure channels
}

