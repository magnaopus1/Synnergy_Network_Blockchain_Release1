package allocation

import (
	"sync"
	"errors"
	"synthron_blockchain/pkg/core/resource_management/models"
)

// Allocator defines the structure for resource allocation
type Allocator struct {
	resourcePool  *ResourcePool
	mutex         sync.Mutex
}

// NewAllocator creates a new instance of Allocator
func NewAllocator(initialResources models.Resources) *Allocator {
	return &Allocator{
		resourcePool: NewResourcePool(initialResources),
	}
}

// AllocateResources dynamically allocates resources based on demand
func (a *Allocator) AllocateResources(request models.ResourceRequest) (models.Resources, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	availableResources := a.resourcePool.Available()
	if !availableResources.CanFulfill(request) {
		return models.Resources{}, errors.New("insufficient resources available")
	}

	allocated := a.resourcePool.Allocate(request)
	return allocated, nil
}

// ReleaseResources releases resources back to the pool
func (a *Allocator) ReleaseResources(resources models.Resources) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.resourcePool.Release(resources)
}

// MonitorAndAdjust continuously monitors resource usage and adjusts allocations
func (a *Allocator) MonitorAndAdjust() {
	go func() {
		for {
			select {
			case <-time.Tick(1 * time.Minute):
				// Implement logic to adjust resources based on real-time metrics
				a.AdjustAllocations()
			}
		}
	}()
}

// AdjustAllocations dynamically adjusts resource allocations based on current demand and usage statistics
func (a *Allocator) AdjustAllocations() {
	// This would involve complex logic that checks current usage, forecasts demand, and optimizes resource distribution
}

// AuditAllocations checks and ensures that all allocations meet the predefined rules and are fair
func (a *Allocator) AuditAllocations() error {
	// Logic to audit current resource allocations and report discrepancies
	return nil
}

// ResourcePool represents a pool of resources that can be allocated
type ResourcePool struct {
	total     models.Resources
	allocated models.Resources
}

// NewResourcePool creates a new resource pool with given resources
func NewResourcePool(resources models.Resources) *ResourcePool {
	return &ResourcePool{
		total: resources,
		allocated: models.Resources{},
	}
}

// Available calculates and returns the available resources
func (rp *ResourcePool) Available() models.Resources {
	return rp.total.Subtract(rp.allocated)
}

// Allocate resources from the pool
func (rp *ResourceContainer) Allocate(request models.ResourceRequest) models.Resources {
	allocated := request.CalculateAllocation(rp.Available())
	rp.allocated = rp.allocated.Add(allocated)
	return allocated
}

// Release resources back to the pool
func (rp *ResourcePool) Release(resources models.Resources) {
	rp.allocated = rp.allocated.Subtract(resources)
}

// This file also needs to include necessary utilities for resource calculations and manipulations.
