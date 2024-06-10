// Package storage_allocation implements dynamic storage pricing within the Synnergy Network blockchain.
package storage_allocation

import (
	"math"
	"sync"

	"github.com/synthron/synthron_blockchain/pkg/util"
)

// DynamicPricing manages the pricing of storage based on demand and supply within the network.
type DynamicPricing struct {
	basePrice float64 // Base price per unit of storage
	priceLock sync.Mutex
}

// NewDynamicPricing initializes a DynamicPricing object with a given base price.
func NewDynamicPricing(basePrice float64) *DynamicPricing {
	return &DynamicPricing{
		basePrice: basePrice,
	}
}

// CalculatePrice computes the price based on current demand and supply.
// The formula adjusts prices dynamically to reflect current market conditions.
func (dp *DynamicPricing) CalculatePrice(currentDemand, totalSupply float64) float64 {
	dp.priceLock.Lock()
	defer dp.priceLock.Unlock()

	if totalSupply == 0 {
		return dp.basePrice // Avoid division by zero; use base price.
	}

	utilizationRate := currentDemand / totalSupply
	newPrice := dp.basePrice * math.Pow(1.1, utilizationRate-0.5) // Exponential adjustment based on utilization.
	dp.basePrice = newPrice                                    // Update the base price for future calculations.

	return newPrice
}

// UpdateBasePrice modifies the base price, which affects future price calculations.
func (dp *DynamicPricing) UpdateBasePrice(newBasePrice float64) {
	dp.priceLock.Lock()
	defer dp.priceLock.Unlock()
	dp.basePrice = newBasePrice
}

// MarketModel encapsulates the market dynamics for storage pricing.
type MarketModel struct {
	currentDemand float64
	totalSupply   float64
	pricing       *DynamicPricing
}

// NewMarketModel creates a new MarketModel with initial market conditions.
func NewMarketModel(initialDemand, initialSupply, initialBasePrice float64) *MarketModel {
	return &MarketModel{
		currentDemand: initialDemand,
		totalSupply:   initialSupply,
		pricing:       NewDynamicPricing(initialBasePrice),
	}
}

// AdjustMarketConditions is used to update demand and supply figures based on network activity.
func (m *MarketModel) AdjustMarketConditions(newDemand, newSupply float64) {
	m.currentDemand = newDemand
	m.totalSupply = newSupply
}

// GetCurrentPrice calculates the current price based on the latest market conditions.
func (m *MarketModel) GetCurrentPrice() float64 {
	return m.pricing.CalculatePrice(m.currentDemand, m.totalSupply)
}

// Example of usage:
func main() {
	market := NewMarketModel(1000, 5000, 0.01)
	price := market.GetCurrentPrice()
	println("Current storage price per unit:", price)

	// Simulate a change in demand or supply
	market.AdjustMarketConditions(2000, 4500)
	price = market.GetCurrentPrice()
	println("Updated storage price per unit:", price)
}
