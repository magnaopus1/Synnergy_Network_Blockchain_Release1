package allocation

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network/pkg/synnergy_network/core/resource_management/auditing"
	"github.com/synnergy_network/pkg/synnergy_network/core/resource_management/contracts"
	"github.com/synnergy_network/pkg/synnergy_network/core/resource_management/resource_pools"
	"github.com/synnergy_network/pkg/synnergy_network/core/resource_management/optimization"
	"github.com/synnergy_network/pkg/synnergy_network/core/resource_management/security"
)

type ResourceAllocator struct {
	mu                sync.Mutex
	pool              *resource_pools.ResourcePool
	contractManager   *contracts.ContractManager
	securityManager   *security.SecurityManager
	auditManager      *auditing.AuditManager
	optimizationManager *optimization.OptimizationManager
}

func NewResourceAllocator(pool *resource_pools.ResourcePool, cm *contracts.ContractManager, sm *security.SecurityManager, am *auditing.AuditManager, om *optimization.OptimizationManager) *ResourceAllocator {
	return &ResourceAllocator{
		pool:              pool,
		contractManager:   cm,
		securityManager:   sm,
		auditManager:      am,
		optimizationManager: om,
	}
}

// Dynamic Allocation Mechanisms
func (ra *ResourceAllocator) AllocateResource(nodeID string, amount int) error {
	ra.mu.Lock()
	defer ra.mu.Unlock()

	// Ensure security checks
	if !ra.securityManager.ValidateNode(nodeID) {
		return fmt.Errorf("invalid node ID: %s", nodeID)
	}

	// Check available resources
	if ra.pool.Available() < amount {
		return fmt.Errorf("not enough resources available")
	}

	// Allocate resources
	if err := ra.pool.Allocate(nodeID, amount); err != nil {
		return fmt.Errorf("allocation failed: %v", err)
	}

	// Log the allocation for auditing purposes
	ra.auditManager.LogAllocation(nodeID, amount)

	// Optimize resource usage
	ra.optimizationManager.Optimize(nodeID, amount)

	return nil
}

func (ra *ResourceAllocator) DeallocateResource(nodeID string, amount int) error {
	ra.mu.Lock()
	defer ra.mu.Unlock()

	// Deallocate resources
	if err := ra.pool.Deallocate(nodeID, amount); err != nil {
		return fmt.Errorf("deallocation failed: %v", err)
	}

	// Log the deallocation for auditing purposes
	ra.auditManager.LogDeallocation(nodeID, amount)

	return nil
}

// Real-time Monitoring and Adaptive Scaling
func (ra *ResourceAllocator) MonitorAndScale() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Real-time resource monitoring
			metrics := ra.pool.Monitor()

			// Adaptive scaling based on metrics
			for nodeID, usage := range metrics {
				if usage > 80 {
					// Scale up resources
					err := ra.AllocateResource(nodeID, 10)
					if err != nil {
						log.Printf("Failed to allocate resources for node %s: %v", nodeID, err)
					}
				} else if usage < 20 {
					// Scale down resources
					err := ra.DeallocateResource(nodeID, 10)
					if err != nil {
						log.Printf("Failed to deallocate resources for node %s: %v", nodeID, err)
					}
				}
			}
		}
	}
}

// Priority-Based Allocation
func (ra *ResourceAllocator) AllocatePriorityResource(nodeID string, amount int, priority int) error {
	ra.mu.Lock()
	defer ra.mu.Unlock()

	// Ensure security checks
	if !ra.securityManager.ValidateNode(nodeID) {
		return fmt.Errorf("invalid node ID: %s", nodeID)
	}

	// Check available resources
	if ra.pool.Available() < amount {
		return fmt.Errorf("not enough resources available")
	}

	// Allocate resources based on priority
	if err := ra.pool.AllocateWithPriority(nodeID, amount, priority); err != nil {
		return fmt.Errorf("allocation failed: %v", err)
	}

	// Log the allocation for auditing purposes
	ra.auditManager.LogPriorityAllocation(nodeID, amount, priority)

	// Optimize resource usage
	ra.optimizationManager.Optimize(nodeID, amount)

	return nil
}

// Smart Contract-Based Resource Management
func (ra *ResourceAllocator) SmartContractResourceAllocation(contractID string, amount int) error {
	ra.mu.Lock()
	defer ra.mu.Unlock()

	// Validate the smart contract
	if !ra.contractManager.ValidateContract(contractID) {
		return fmt.Errorf("invalid contract ID: %s", contractID)
	}

	// Check available resources
	if ra.pool.Available() < amount {
		return fmt.Errorf("not enough resources available")
	}

	// Allocate resources as per smart contract
	if err := ra.contractManager.ExecuteContract(contractID, amount); err != nil {
		return fmt.Errorf("contract execution failed: %v", err)
	}

	// Log the contract execution for auditing purposes
	ra.auditManager.LogContractExecution(contractID, amount)

	// Optimize resource usage
	ra.optimizationManager.Optimize(contractID, amount)

	return nil
}

func (ra *ResourceAllocator) GetResourceStatus() map[string]int {
	ra.mu.Lock()
	defer ra.mu.Unlock()

	return ra.pool.Status()
}

func (ra *ResourceAllocator) AuditResources() {
	ra.mu.Lock()
	defer ra.mu.Unlock()

	ra.auditManager.ConductAudit(ra.pool.Status())
}
