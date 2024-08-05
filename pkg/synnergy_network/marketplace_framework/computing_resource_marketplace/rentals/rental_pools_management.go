package rentals

import (
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// PoolStatus represents the status of a rental pool
type PoolStatus string

const (
	Active   PoolStatus = "active"
	Inactive PoolStatus = "inactive"
)

// RentalPool represents a pool of resources available for rent
type RentalPool struct {
	ID          string
	Name        string
	Description string
	OwnerID     string
	Status      PoolStatus
	Resources   []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// RentalPoolManager manages rental pools
type RentalPoolManager struct {
	mu         sync.Mutex
	rentalPools map[string]RentalPool
}

// NewRentalPoolManager initializes a new RentalPoolManager
func NewRentalPoolManager() *RentalPoolManager {
	return &RentalPoolManager{
		rentalPools: make(map[string]RentalPool),
	}
}

// CreatePool creates a new rental pool
func (rpm *RentalPoolManager) CreatePool(name, description, ownerID string, resources []string) (string, error) {
	rpm.mu.Lock()
	defer rpm.mu.Unlock()

	poolID := generateID(name, ownerID, time.Now())
	pool := RentalPool{
		ID:          poolID,
		Name:        name,
		Description: description,
		OwnerID:     ownerID,
		Status:      Active,
		Resources:   resources,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	rpm.rentalPools[poolID] = pool
	return poolID, nil
}

// UpdatePool updates the details of a rental pool
func (rpm *RentalPoolManager) UpdatePool(poolID, name, description string, resources []string) error {
	rpm.mu.Lock()
	defer rpm.mu.Unlock()

	pool, exists := rpm.rentalPools[poolID]
	if !exists {
		return errors.New("rental pool not found")
	}

	pool.Name = name
	pool.Description = description
	pool.Resources = resources
	pool.UpdatedAt = time.Now()

	rpm.rentalPools[poolID] = pool
	return nil
}

// DeletePool deletes a rental pool
func (rpm *RentalPoolManager) DeletePool(poolID string) error {
	rpm.mu.Lock()
	defer rpm.mu.Unlock()

	_, exists := rpm.rentalPools[poolID]
	if !exists {
		return errors.New("rental pool not found")
	}

	delete(rpm.rentalPools, poolID)
	return nil
}

// GetPool retrieves the details of a rental pool
func (rpm *RentalPoolManager) GetPool(poolID string) (RentalPool, error) {
	rpm.mu.Lock()
	defer rpm.mu.Unlock()

	pool, exists := rpm.rentalPools[poolID]
	if !exists {
		return RentalPool{}, errors.New("rental pool not found")
	}

	return pool, nil
}

// ListActivePools lists all active rental pools
func (rpm *RentalPoolManager) ListActivePools() []RentalPool {
	rpm.mu.Lock()
	defer rpm.mu.Unlock()

	var activePools []RentalPool
	for _, pool := range rpm.rentalPools {
		if pool.Status == Active {
			activePools = append(activePools, pool)
		}
	}
	return activePools
}

// DeactivatePool deactivates a rental pool
func (rpm *RentalPoolManager) DeactivatePool(poolID string) error {
	rpm.mu.Lock()
	defer rpm.mu.Unlock()

	pool, exists := rpm.rentalPools[poolID]
	if !exists {
		return errors.New("rental pool not found")
	}

	pool.Status = Inactive
	pool.UpdatedAt = time.Now()
	rpm.rentalPools[poolID] = pool

	return nil
}

// ActivatePool activates a rental pool
func (rpm *RentalPoolManager) ActivatePool(poolID string) error {
	rpm.mu.Lock()
	defer rpm.mu.Unlock()

	pool, exists := rpm.rentalPools[poolID]
	if !exists {
		return errors.New("rental pool not found")
	}

	pool.Status = Active
	pool.UpdatedAt = time.Now()
	rpm.rentalPools[poolID] = pool

	return nil
}

// generateID generates a unique ID for a rental pool
func generateID(name, ownerID string, timestamp time.Time) string {
	input := name + ownerID + timestamp.String()
	hash := argon2.IDKey([]byte(input), []byte("somesalt"), 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}
