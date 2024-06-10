package management

import (
	"sync"
	"time"

	"github.com/synthron_blockchain/pkg/layer0/core/resource_management/allocation"
	"github.com/synthron_blockchain/pkg/layer0/core/resource_management/contracts"
)

// Controller orchestrates resource management including allocation, monitoring, and adjustment.
type Controller struct {
	allocator  *allocation.Allocator
	monitor    *Monitor
	contract   *contracts.ContractManager
	lock       sync.Mutex
	lastUpdate time.Time
}

// NewController creates a new Controller instance with necessary dependencies.
func NewController(allocator *allocation.Allocator, monitor *Monitor, contract *contracts.ContractManager) *Controller {
	return &Controller{
		allocator:  allocator,
		monitor:    monitor,
		contract:   contract,
		lastUpdate: time.Now(),
	}
}

// ManageResources is the core function that orchestrates the dynamic allocation and reallocation of resources.
func (c *Controller) ManageResources() {
	c.lock.Lock()
	defer c.lock.Unlock()

	// Monitor resource usage and demand
	resourceStatus := c.monitor.CheckResources()
	demands := c.monitor.EvaluateDemands(resourceStatus)

	// Adjust resources based on current demands and policy constraints
	adjustments, err := c.allocator.CalculateAdjustments(demands)
	if err != nil {
		// Log error and return; in a production environment, consider a retry mechanism or alerting
		log.Printf("Failed to calculate resource adjustments: %v", err)
		return
	}

	// Apply the calculated adjustments through smart contracts
	for _, adj := range adjustments {
		if err := c.contract.ExecuteAdjustment(adj); err != nil {
			log.Printf("Failed to execute resource adjustment: %v", err)
			continue
		}
	}

	// Update the last time resources were managed
	c.lastUpdate = time.Now()
}

// MonitorAdjustmentEffectiveness periodically assesses the effectiveness of recent resource adjustments.
func (c *Controller) MonitorAdjustmentEffectiveness() {
	c.lock.Lock()
	defer c.lock.Unlock()

	// Evaluate the impact of recent adjustments
	effectiveness := c.monitor.EvaluateAdjustmentEffectiveness(c.lastUpdate)
	if effectiveness.NeedsReevaluation {
		c.ManageResources() // Re-run resource management if adjustments were not effective
	}
}

// Run starts the resource management process and periodically checks for adjustment effectiveness.
func (c *Controller) Run(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.MonitorAdjustmentEffectiveness()
		}
	}
}
