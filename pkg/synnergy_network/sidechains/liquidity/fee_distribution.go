package liquidity

import (
	"errors"
	"sync"
)

// FeeDistribution manages the distribution of fees within the liquidity sidechain
type FeeDistribution struct {
	mu           sync.RWMutex
	totalFees    float64
	allocations  map[string]float64
	participants map[string]float64
}

// NewFeeDistribution creates a new FeeDistribution instance
func NewFeeDistribution() *FeeDistribution {
	return &FeeDistribution{
		allocations:  make(map[string]float64),
		participants: make(map[string]float64),
	}
}

// AddParticipant adds a new participant with a specific allocation percentage
func (fd *FeeDistribution) AddParticipant(participantID string, allocation float64) error {
	if allocation <= 0 || allocation > 1 {
		return errors.New("allocation must be a value between 0 and 1")
	}

	fd.mu.Lock()
	defer fd.mu.Unlock()

	fd.allocations[participantID] = allocation
	fd.participants[participantID] = 0 // Initialize with zero fees
	return nil
}

// RemoveParticipant removes a participant
func (fd *FeeDistribution) RemoveParticipant(participantID string) error {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	if _, exists := fd.allocations[participantID]; !exists {
		return errors.New("participant not found")
	}

	delete(fd.allocations, participantID)
	delete(fd.participants, participantID)
	return nil
}

// DistributeFees distributes the collected fees among participants based on their allocations
func (fd *FeeDistribution) DistributeFees() error {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	if fd.totalFees == 0 {
		return errors.New("no fees to distribute")
	}

	for participantID, allocation := range fd.allocations {
		fd.participants[participantID] += fd.totalFees * allocation
	}

	fd.totalFees = 0 // Reset total fees after distribution
	return nil
}

// CollectFee collects a fee to be distributed later
func (fd *FeeDistribution) CollectFee(amount float64) error {
	if amount <= 0 {
		return errors.New("fee amount must be positive")
	}

	fd.mu.Lock()
	defer fd.mu.Unlock()

	fd.totalFees += amount
	return nil
}

// GetParticipantFees gets the total fees collected for a specific participant
func (fd *FeeDistribution) GetParticipantFees(participantID string) (float64, error) {
	fd.mu.RLock()
	defer fd.mu.RUnlock()

	fees, exists := fd.participants[participantID]
	if !exists {
		return 0, errors.New("participant not found")
	}

	return fees, nil
}

// GetTotalFees gets the total fees collected
func (fd *FeeDistribution) GetTotalFees() float64 {
	fd.mu.RLock()
	defer fd.mu.RUnlock()

	return fd.totalFees
}

// ClearParticipantFees clears the collected fees for a specific participant
func (fd *FeeDistribution) ClearParticipantFees(participantID string) error {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	if _, exists := fd.participants[participantID]; !exists {
		return errors.New("participant not found")
	}

	fd.participants[participantID] = 0
	return nil
}

// ValidateAllocation ensures that the total allocation does not exceed 1 (100%)
func (fd *FeeDistribution) ValidateAllocation() error {
	fd.mu.RLock()
	defer fd.mu.RUnlock()

	totalAllocation := 0.0
	for _, allocation := range fd.allocations {
		totalAllocation += allocation
	}

	if totalAllocation > 1 {
		return errors.New("total allocation exceeds 100%")
	}

	return nil
}

// AdjustAllocation adjusts the allocation for a specific participant
func (fd *FeeDistribution) AdjustAllocation(participantID string, newAllocation float64) error {
	if newAllocation <= 0 || newAllocation > 1 {
		return errors.New("allocation must be a value between 0 and 1")
	}

	fd.mu.Lock()
	defer fd.mu.Unlock()

	if _, exists := fd.allocations[participantID]; !exists {
		return errors.New("participant not found")
	}

	fd.allocations[participantID] = newAllocation
	return fd.ValidateAllocation()
}

// ListParticipants returns a list of all participants with their allocations and fees
func (fd *FeeDistribution) ListParticipants() map[string]struct {
	Allocation float64
	Fees       float64
} {
	fd.mu.RLock()
	defer fd.mu.RUnlock()

	participants := make(map[string]struct {
		Allocation float64
		Fees       float64
	})

	for participantID, allocation := range fd.allocations {
		participants[participantID] = struct {
			Allocation float64
			Fees       float64
		}{
			Allocation: allocation,
			Fees:       fd.participants[participantID],
		}
	}

	return participants
}
