package trading

import (
	"errors"
	"sync"
	"time"
)

// Resource represents a single computing resource in the marketplace.
type Resource struct {
	ID          string
	Name        string
	Description string
	SpotPrice   float64
	ReservedPrice float64
	OwnerID     string
	Available   bool
}

// PricingType defines the type of pricing for a resource.
type PricingType int

const (
	Spot PricingType = iota
	Reserved
)

// SpotReservedPricingManager manages spot and reserved pricing for resources.
type SpotReservedPricingManager struct {
	mu        sync.Mutex
	resources map[string]Resource
	pricing   map[string]PricingType
}

// NewSpotReservedPricingManager initializes a new SpotReservedPricingManager.
func NewSpotReservedPricingManager() *SpotReservedPricingManager {
	return &SpotReservedPricingManager{
		resources: make(map[string]Resource),
		pricing:   make(map[string]PricingType),
	}
}

// AddResource adds a new resource to the marketplace.
func (srpm *SpotReservedPricingManager) AddResource(id, name, description, ownerID string, spotPrice, reservedPrice float64) error {
	srpm.mu.Lock()
	defer srpm.mu.Unlock()

	if _, exists := srpm.resources[id]; exists {
		return errors.New("resource with this ID already exists")
	}

	resource := Resource{
		ID:           id,
		Name:         name,
		Description:  description,
		SpotPrice:    spotPrice,
		ReservedPrice: reservedPrice,
		OwnerID:      ownerID,
		Available:    true,
	}

	srpm.resources[id] = resource
	return nil
}

// RemoveResource removes a resource from the marketplace.
func (srpm *SpotReservedPricingManager) RemoveResource(id string) error {
	srpm.mu.Lock()
	defer srpm.mu.Unlock()

	if _, exists := srpm.resources[id]; !exists {
		return errors.New("resource not found")
	}

	delete(srpm.resources, id)
	return nil
}

// SetPricing sets the pricing type for a resource.
func (srpm *SpotReservedPricingManager) SetPricing(id string, pricingType PricingType) error {
	srpm.mu.Lock()
	defer srpm.mu.Unlock()

	if _, exists := srpm.resources[id]; !exists {
		return errors.New("resource not found")
	}

	srpm.pricing[id] = pricingType
	return nil
}

// GetPricing gets the pricing type for a resource.
func (srpm *SpotReservedPricingManager) GetPricing(id string) (PricingType, error) {
	srpm.mu.Lock()
	defer srpm.mu.Unlock()

	pricingType, exists := srpm.pricing[id]
	if !exists {
		return 0, errors.New("pricing not set for this resource")
	}

	return pricingType, nil
}

// ListResources lists all resources with their pricing details.
func (srpm *SpotReservedPricingManager) ListResources() []Resource {
	srpm.mu.Lock()
	defer srpm.mu.Unlock()

	var resources []Resource
	for _, resource := range srpm.resources {
		resources = append(resources, resource)
	}
	return resources
}

// PurchaseResource handles the purchase of a resource based on its pricing type.
func (srpm *SpotReservedPricingManager) PurchaseResource(resourceID, buyerID string, pricingType PricingType) error {
	srpm.mu.Lock()
	defer srpm.mu.Unlock()

	resource, exists := srpm.resources[resourceID]
	if !exists {
		return errors.New("resource not found")
	}

	if !resource.Available {
		return errors.New("resource is not available")
	}

	currentPricingType, exists := srpm.pricing[resourceID]
	if !exists || currentPricingType != pricingType {
		return errors.New("pricing type mismatch")
	}

	// Perform the purchase logic, e.g., transferring ownership and processing payment
	resource.Available = false
	srpm.resources[resourceID] = resource

	return nil
}

// UpdateSpotPrice updates the spot price of a resource.
func (srpm *SpotReservedPricingManager) UpdateSpotPrice(id string, spotPrice float64) error {
	srpm.mu.Lock()
	defer srpm.mu.Unlock()

	resource, exists := srpm.resources[id]
	if !exists {
		return errors.New("resource not found")
	}

	resource.SpotPrice = spotPrice
	srpm.resources[id] = resource
	return nil
}

// UpdateReservedPrice updates the reserved price of a resource.
func (srpm *SpotReservedPricingManager) UpdateReservedPrice(id string, reservedPrice float64) error {
	srpm.mu.Lock()
	defer srpm.mu.Unlock()

	resource, exists := srpm.resources[id]
	if !exists {
		return errors.New("resource not found")
	}

	resource.ReservedPrice = reservedPrice
	srpm.resources[id] = resource
	return nil
}

// generateID generates a unique ID for resources and bundles.
func generateID(parts ...interface{}) string {
	var input string
	for _, part := range parts {
		input += part.(string)
	}
	return hex.EncodeToString(argon2.IDKey([]byte(input), []byte("somesalt"), 1, 64*1024, 4, 32))
}
