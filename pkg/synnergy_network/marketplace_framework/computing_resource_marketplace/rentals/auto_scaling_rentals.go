package rentals

import (
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"encoding/hex"
)

// Rental represents a rental in the system
type Rental struct {
	ID            string
	UserID        string
	ResourceID    string
	StartTime     time.Time
	EndTime       time.Time
	Status        string
	AutoScale     bool
}

// RentalManager manages rentals
type RentalManager struct {
	mu          sync.Mutex
	rentals     map[string]Rental
	users       map[string]string
	resources   map[string]string
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
		users:       make(map[string]string),
		resources:   make(map[string]string),
		autoScalers: make(map[string]*AutoScaler),
	}
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
		Status:     "active",
		AutoScale:  autoScale,
	}

	rm.rentals[rentalID] = rental
	return rentalID, nil
}

// UpdateRentalStatus updates the status of a rental
func (rm *RentalManager) UpdateRentalStatus(rentalID, status string) error {
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
