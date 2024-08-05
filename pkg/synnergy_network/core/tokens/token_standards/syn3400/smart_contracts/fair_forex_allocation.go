package smart_contracts

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// FairForexAllocation represents the structure for fair allocation of Forex pairs.
type FairForexAllocation struct {
	AllocationID      string         `json:"allocation_id"`
	Owner             string         `json:"owner"`
	Allocations       []Allocation   `json:"allocations"`
	DeploymentDate    time.Time      `json:"deployment_date"`
	LastUpdatedDate   time.Time      `json:"last_updated_date"`
	ActivationStatus  bool           `json:"activation_status"`
	mutex             sync.Mutex
}

// Allocation represents a single allocation within the fair allocation mechanism.
type Allocation struct {
	AllocationID string    `json:"allocation_id"`
	UserID       string    `json:"user_id"`
	ForexPair    string    `json:"forex_pair"`
	Percentage   float64   `json:"percentage"`
	CreatedAt    time.Time `json:"created_at"`
}

// FairForexAllocationManager manages fair Forex allocations.
type FairForexAllocationManager struct {
	Allocations map[string]*FairForexAllocation
	mutex       sync.Mutex
}

// NewFairForexAllocationManager initializes the FairForexAllocationManager.
func NewFairForexAllocationManager() *FairForexAllocationManager {
	return &FairForexAllocationManager{
		Allocations: make(map[string]*FairForexAllocation),
	}
}

// AddAllocation adds a new fair Forex allocation.
func (ffam *FairForexAllocationManager) AddAllocation(allocation *FairForexAllocation) error {
	ffam.mutex.Lock()
	defer ffam.mutex.Unlock()

	if _, exists := ffam.Allocations[allocation.AllocationID]; exists {
		return errors.New("allocation already exists")
	}

	ffam.Allocations[allocation.AllocationID] = allocation
	ffam.logAllocationEvent(allocation, "ALLOCATION_ADDED")

	return nil
}

// UpdateAllocation updates an existing fair Forex allocation.
func (ffam *FairForexAllocationManager) UpdateAllocation(allocation *FairForexAllocation) error {
	ffam.mutex.Lock()
	defer ffam.mutex.Unlock()

	if _, exists := ffam.Allocations[allocation.AllocationID]; !exists {
		return errors.New("allocation not found")
	}

	ffam.Allocations[allocation.AllocationID] = allocation
	ffam.logAllocationEvent(allocation, "ALLOCATION_UPDATED")

	return nil
}

// ActivateAllocation activates a fair Forex allocation.
func (ffam *FairForexAllocationManager) ActivateAllocation(allocationID string) error {
	ffam.mutex.Lock()
	defer ffam.mutex.Unlock()

	allocation, exists := ffam.Allocations[allocationID]
	if !exists {
		return errors.New("allocation not found")
	}

	allocation.ActivationStatus = true
	allocation.LastUpdatedDate = time.Now()
	ffam.Allocations[allocationID] = allocation
	ffam.logAllocationEvent(allocation, "ALLOCATION_ACTIVATED")

	return nil
}

// DeactivateAllocation deactivates a fair Forex allocation.
func (ffam *FairForexAllocationManager) DeactivateAllocation(allocationID string) error {
	ffam.mutex.Lock()
	defer ffam.mutex.Unlock()

	allocation, exists := ffam.Allocations[allocationID]
	if !exists {
		return errors.New("allocation not found")
	}

	allocation.ActivationStatus = false
	allocation.LastUpdatedDate = time.Now()
	ffam.Allocations[allocationID] = allocation
	ffam.logAllocationEvent(allocation, "ALLOCATION_DEACTIVATED")

	return nil
}

// GetAllocation retrieves a fair Forex allocation by ID.
func (ffam *FairForexAllocationManager) GetAllocation(allocationID string) (*FairForexAllocation, error) {
	ffam.mutex.Lock()
	defer ffam.mutex.Unlock()

	allocation, exists := ffam.Allocations[allocationID]
	if !exists {
		return nil, errors.New("allocation not found")
	}

	return allocation, nil
}

// ListAllocations lists all fair Forex allocations.
func (ffam *FairForexAllocationManager) ListAllocations() []*FairForexAllocation {
	ffam.mutex.Lock()
	defer ffam.mutex.Unlock()

	allocations := make([]*FairForexAllocation, 0, len(ffam.Allocations))
	for _, allocation := range ffam.Allocations {
		allocations = append(allocations, allocation)
	}
	return allocations
}

// AddUserAllocation adds an allocation to a user within a fair Forex allocation.
func (ffam *FairForexAllocationManager) AddUserAllocation(allocationID string, userAllocation Allocation) error {
	ffam.mutex.Lock()
	defer ffam.mutex.Unlock()

	allocation, exists := ffam.Allocations[allocationID]
	if !exists {
		return errors.New("allocation not found")
	}

	userAllocation.AllocationID = generateUniqueID()
	userAllocation.CreatedAt = time.Now()
	allocation.Allocations = append(allocation.Allocations, userAllocation)
	allocation.LastUpdatedDate = time.Now()
	ffam.Allocations[allocationID] = allocation
	ffam.logAllocationEvent(allocation, "USER_ALLOCATION_ADDED")

	return nil
}

// RemoveUserAllocation removes an allocation from a user within a fair Forex allocation.
func (ffam *FairForexAllocationManager) RemoveUserAllocation(allocationID, userAllocationID string) error {
	ffam.mutex.Lock()
	defer ffam.mutex.Unlock()

	allocation, exists := ffam.Allocations[allocationID]
	if !exists {
		return errors.New("allocation not found")
	}

	for i, alloc := range allocation.Allocations {
		if alloc.AllocationID == userAllocationID {
			allocation.Allocations = append(allocation.Allocations[:i], allocation.Allocations[i+1:]...)
			allocation.LastUpdatedDate = time.Now()
			ffam.Allocations[allocationID] = allocation
			ffam.logAllocationEvent(allocation, "USER_ALLOCATION_REMOVED")
			return nil
		}
	}

	return errors.New("user allocation not found")
}

// EvaluateAllocation evaluates all allocations of a fair Forex allocation.
func (ffam *FairForexAllocationManager) EvaluateAllocation(allocationID string) (bool, error) {
	ffam.mutex.Lock()
	defer ffam.mutex.Unlock()

	allocation, exists := ffam.Allocations[allocationID]
	if !exists {
		return false, errors.New("allocation not found")
	}

	if !allocation.ActivationStatus {
		return false, errors.New("allocation is not activated")
	}

	allAllocationsFair := true
	for _, alloc := range allocation.Allocations {
		allocationFair, err := evaluateUserAllocation(alloc)
		if err != nil {
			return false, err
		}
		if !allocationFair {
			allAllocationsFair = false
		}
	}

	ffam.logAllocationEvent(allocation, "ALLOCATION_EVALUATED")

	return allAllocationsFair, nil
}

// evaluateUserAllocation evaluates a single user allocation (dummy implementation).
func evaluateUserAllocation(allocation Allocation) (bool, error) {
	// Dummy implementation, should be extended with real business logic.
	// For instance, checking if the allocated percentage exceeds a certain threshold.
	if allocation.Percentage < 0 || allocation.Percentage > 100 {
		return false, errors.New("invalid allocation percentage")
	}
	return true, nil
}

// logAllocationEvent logs events related to fair Forex allocations.
func (ffam *FairForexAllocationManager) logAllocationEvent(allocation *FairForexAllocation, eventType string) {
	event := map[string]interface{}{
		"event_type":        eventType,
		"allocation_id":     allocation.AllocationID,
		"owner":             allocation.Owner,
		"timestamp":         time.Now().UTC(),
		"activation_status": allocation.ActivationStatus,
	}
	eventData, _ := json.Marshal(event)
	fmt.Println(string(eventData))
}

// generateUniqueID generates a unique identifier (dummy implementation).
func generateUniqueID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
