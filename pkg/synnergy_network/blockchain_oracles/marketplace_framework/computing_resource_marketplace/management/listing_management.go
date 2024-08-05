package management

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ListingStatus represents the status of a listing
type ListingStatus int

const (
	Active ListingStatus = iota
	Inactive
	Expired
)

// Listing represents a listing in the marketplace
type Listing struct {
	ID          string
	OwnerID     string
	Description string
	Price       float64
	Status      ListingStatus
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// ListingManager manages listings in the marketplace
type ListingManager struct {
	mu        sync.Mutex
	listings  map[string]*Listing
	ownerMap  map[string][]*Listing
	nextID    int
}

// NewListingManager initializes a new ListingManager
func NewListingManager() *ListingManager {
	return &ListingManager{
		listings: make(map[string]*Listing),
		ownerMap: make(map[string][]*Listing),
		nextID:   1,
	}
}

// CreateListing creates a new listing
func (lm *ListingManager) CreateListing(ownerID, description string, price float64, durationDays int) (*Listing, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	id := lm.generateID()
	listing := &Listing{
		ID:          id,
		OwnerID:     ownerID,
		Description: description,
		Price:       price,
		Status:      Active,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().AddDate(0, 0, durationDays),
	}

	lm.listings[id] = listing
	lm.ownerMap[ownerID] = append(lm.ownerMap[ownerID], listing)

	return listing, nil
}

// UpdateListing updates an existing listing
func (lm *ListingManager) UpdateListing(id, description string, price float64) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	listing, exists := lm.listings[id]
	if !exists {
		return errors.New("listing not found")
	}

	if listing.Status != Active {
		return errors.New("listing is not active")
	}

	listing.Description = description
	listing.Price = price

	return nil
}

// DeactivateListing deactivates an active listing
func (lm *ListingManager) DeactivateListing(id string) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	listing, exists := lm.listings[id]
	if !exists {
		return errors.New("listing not found")
	}

	if listing.Status != Active {
		return errors.New("listing is not active")
	}

	listing.Status = Inactive

	return nil
}

// GetListing retrieves a listing by ID
func (lm *ListingManager) GetListing(id string) (*Listing, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	listing, exists := lm.listings[id]
	if !exists {
		return nil, errors.New("listing not found")
	}

	return listing, nil
}

// GetListingsByOwner retrieves all listings for a given owner
func (lm *ListingManager) GetListingsByOwner(ownerID string) ([]*Listing, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	listings, exists := lm.ownerMap[ownerID]
	if !exists {
		return nil, errors.New("no listings found for the owner")
	}

	return listings, nil
}

// RemoveExpiredListings removes listings that have expired
func (lm *ListingManager) RemoveExpiredListings() {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	now := time.Now()
	for id, listing := range lm.listings {
		if listing.ExpiresAt.Before(now) {
			listing.Status = Expired
		}
	}
}

// ListActiveListings returns all active listings
func (lm *ListingManager) ListActiveListings() []*Listing {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	var activeListings []*Listing
	for _, listing := range lm.listings {
		if listing.Status == Active && listing.ExpiresAt.After(time.Now()) {
			activeListings = append(activeListings, listing)
		}
	}

	return activeListings
}

// generateID generates a unique ID for a listing
func (lm *ListingManager) generateID() string {
	id := fmt.Sprintf("L-%d", lm.nextID)
	lm.nextID++
	return id
}
