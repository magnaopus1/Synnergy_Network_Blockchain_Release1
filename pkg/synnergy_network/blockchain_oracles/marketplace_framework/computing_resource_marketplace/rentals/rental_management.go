package rentals

import (
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// RentalStatus represents the status of a rental
type RentalStatus string

const (
	Active     RentalStatus = "active"
	Completed  RentalStatus = "completed"
	Cancelled  RentalStatus = "cancelled"
)

// Rental represents a rental in the system
type Rental struct {
	ID            string
	UserID        string
	ResourceID    string
	StartTime     time.Time
	EndTime       time.Time
	Status        RentalStatus
	AutoScale     bool
}

// RentalManager manages rentals
type RentalManager struct {
	mu       sync.Mutex
	rentals  map[string]Rental
	autoScalers map[string]*AutoScaler
}

// AutoScaler handles the auto-scaling logic
type AutoScaler struct {
	rentalID     string
	active       bool
	scalingLogic func(resourceID string) error
	stopChan     chan bool
}

// NewRentalManager initializes a new RentalManager
func NewRentalManager() *RentalManager {
	return &RentalManager{
		rentals:     make(map[string]Rental),
		autoScalers: make(map[string]*AutoScaler),
	}
}

// AddRental adds a new rental to the system
func (rm *RentalManager) AddRental(userID, resourceID string, startTime, endTime time.Time, autoScale bool) (string, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rentalID := generateID(userID, resourceID, startTime)
	rental := Rental{
		ID:         rentalID,
		UserID:     userID,
		ResourceID: resourceID,
		StartTime:  startTime,
		EndTime:    endTime,
		Status:     Active,
		AutoScale:  autoScale,
	}

	rm.rentals[rentalID] = rental
	return rentalID, nil
}

// UpdateRentalStatus updates the status of a rental
func (rm *RentalManager) UpdateRentalStatus(rentalID string, status RentalStatus) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rental, exists := rm.rentals[rentalID]
	if !exists {
		return errors.New("rental not found")
	}

	rental.Status = status
	rm.rentals[rentalID] = rental
	return nil
}

// GetRental retrieves the details of a rental
func (rm *RentalManager) GetRental(rentalID string) (Rental, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rental, exists := rm.rentals[rentalID]
	if !exists {
		return Rental{}, errors.New("rental not found")
	}

	return rental, nil
}

// StartAutoScaler starts an auto-scaler for a rental
func (rm *RentalManager) StartAutoScaler(rentalID string, scalingLogic func(resourceID string) error) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rental, exists := rm.rentals[rentalID]
	if !exists {
		return errors.New("rental not found")
	}

	if rental.AutoScale {
		autoScaler := &AutoScaler{
			rentalID:     rentalID,
			active:       true,
			scalingLogic: scalingLogic,
			stopChan:     make(chan bool),
		}
		rm.autoScalers[rentalID] = autoScaler

		go autoScaler.start()
		return nil
	}

	return errors.New("auto-scaling not enabled for this rental")
}

// StopAutoScaler stops the auto-scaler for a rental
func (rm *RentalManager) StopAutoScaler(rentalID string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	autoScaler, exists := rm.autoScalers[rentalID]
	if !exists {
		return errors.New("auto-scaler not found")
	}

	autoScaler.stop()
	delete(rm.autoScalers, rentalID)
	return nil
}

// generateID generates a unique ID for a rental
func generateID(userID, resourceID string, startTime time.Time) string {
	input := userID + resourceID + startTime.String()
	hash := argon2.IDKey([]byte(input), []byte("somesalt"), 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}

// start begins the auto-scaling process
func (as *AutoScaler) start() {
	for {
		select {
		case <-as.stopChan:
			return
		default:
			err := as.scalingLogic(as.rentalID)
			if err != nil {
				// Handle error (e.g., log it)
			}
			time.Sleep(10 * time.Minute) // Adjust the interval as needed
		}
	}
}

// stop stops the auto-scaling process
func (as *AutoScaler) stop() {
	as.active = false
	as.stopChan <- true
}

// ListActiveRentals lists all active rentals
func (rm *RentalManager) ListActiveRentals() []Rental {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	var activeRentals []Rental
	for _, rental := range rm.rentals {
		if rental.Status == Active {
			activeRentals = append(activeRentals, rental)
		}
	}
	return activeRentals
}

// CancelRental cancels a rental
func (rm *RentalManager) CancelRental(rentalID string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rental, exists := rm.rentals[rentalID]
	if !exists {
		return errors.New("rental not found")
	}

	if rental.Status != Active {
		return errors.New("only active rentals can be cancelled")
	}

	rental.Status = Cancelled
	rm.rentals[rentalID] = rental

	if rental.AutoScale {
		rm.StopAutoScaler(rentalID)
	}

	return nil
}

// CompleteRental completes a rental
func (rm *RentalManager) CompleteRental(rentalID string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rental, exists := rm.rentals[rentalID]
	if !exists {
		return errors.New("rental not found")
	}

	if rental.Status != Active {
		return errors.New("only active rentals can be completed")
	}

	rental.Status = Completed
	rm.rentals[rentalID] = rental

	if rental.AutoScale {
		rm.StopAutoScaler(rentalID)
	}

	return nil
}
