package pricing

import (
	"errors"
	"sync"
	"time"
)

// PricingModel represents the dynamic pricing model for resources
type PricingModel struct {
	BasePrice   float64
	UsageFactor float64
	DemandFactor float64
	VolatilityFactor float64
}

// DynamicPricingManager manages the dynamic pricing of resources in the marketplace
type DynamicPricingManager struct {
	mu         sync.Mutex
	pricing    map[string]*PricingModel
	adjustmentInterval time.Duration
	stopCh     chan bool
}

// NewDynamicPricingManager initializes a new DynamicPricingManager
func NewDynamicPricingManager(interval time.Duration) *DynamicPricingManager {
	return &DynamicPricingManager{
		pricing:    make(map[string]*PricingModel),
		adjustmentInterval: interval,
		stopCh:     make(chan bool),
	}
}

// AddPricingModel adds a new pricing model for a resource
func (dpm *DynamicPricingManager) AddPricingModel(resourceID string, basePrice, usageFactor, demandFactor, volatilityFactor float64) error {
	dpm.mu.Lock()
	defer dpm.mu.Unlock()

	if basePrice <= 0 {
		return errors.New("base price must be greater than zero")
	}

	dpm.pricing[resourceID] = &PricingModel{
		BasePrice:   basePrice,
		UsageFactor: usageFactor,
		DemandFactor: demandFactor,
		VolatilityFactor: volatilityFactor,
	}
	return nil
}

// UpdatePricingModel updates an existing pricing model
func (dpm *DynamicPricingManager) UpdatePricingModel(resourceID string, basePrice, usageFactor, demandFactor, volatilityFactor float64) error {
	dpm.mu.Lock()
	defer dpm.mu.Unlock()

	model, exists := dpm.pricing[resourceID]
	if !exists {
		return errors.New("pricing model not found")
	}

	model.BasePrice = basePrice
	model.UsageFactor = usageFactor
	model.DemandFactor = demandFactor
	model.VolatilityFactor = volatilityFactor
	return nil
}

// RemovePricingModel removes a pricing model
func (dpm *DynamicPricingManager) RemovePricingModel(resourceID string) error {
	dpm.mu.Lock()
	defer dpm.mu.Unlock()

	_, exists := dpm.pricing[resourceID]
	if !exists {
		return errors.New("pricing model not found")
	}

	delete(dpm.pricing, resourceID)
	return nil
}

// GetPrice calculates the current price of a resource
func (dpm *DynamicPricingManager) GetPrice(resourceID string, usage, demand, volatility float64) (float64, error) {
	dpm.mu.Lock()
	defer dpm.mu.Unlock()

	model, exists := dpm.pricing[resourceID]
	if !exists {
		return 0, errors.New("pricing model not found")
	}

	price := model.BasePrice + (model.UsageFactor * usage) + (model.DemandFactor * demand) + (model.VolatilityFactor * volatility)
	return price, nil
}

// StartDynamicPricing starts the dynamic pricing adjustments at regular intervals
func (dpm *DynamicPricingManager) StartDynamicPricing() {
	go func() {
		ticker := time.NewTicker(dpm.adjustmentInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				dpm.adjustPrices()
			case <-dpm.stopCh:
				return
			}
		}
	}()
}

// StopDynamicPricing stops the dynamic pricing adjustments
func (dpm *DynamicPricingManager) StopDynamicPricing() {
	dpm.stopCh <- true
}

// adjustPrices adjusts the prices of all resources based on current usage, demand, and volatility
func (dpm *DynamicPricingManager) adjustPrices() {
	dpm.mu.Lock()
	defer dpm.mu.Unlock()

	for resourceID, model := range dpm.pricing {
		// Simulate obtaining current usage, demand, and volatility
		usage := getCurrentUsage(resourceID)
		demand := getCurrentDemand(resourceID)
		volatility := getCurrentVolatility(resourceID)

		newPrice := model.BasePrice + (model.UsageFactor * usage) + (model.DemandFactor * demand) + (model.VolatilityFactor * volatility)
		model.BasePrice = newPrice
	}
}

// getCurrentUsage simulates obtaining the current usage of a resource
func getCurrentUsage(resourceID string) float64 {
	// Simulated logic for obtaining current usage
	return 0.8 // Placeholder value
}

// getCurrentDemand simulates obtaining the current demand for a resource
func getCurrentDemand(resourceID string) float64 {
	// Simulated logic for obtaining current demand
	return 1.2 // Placeholder value
}

// getCurrentVolatility simulates obtaining the current volatility for a resource
func getCurrentVolatility(resourceID string) float64 {
	// Simulated logic for obtaining current volatility
	return 0.5 // Placeholder value
}
