package resource_markets

import (
    "fmt"
    "log"
    "math"
    "time"
    "github.com/synnergy_network/core/contracts"
    "github.com/synnergy_network/core/resource_security"
    "github.com/synnergy_network/core/auditing"
    "github.com/synnergy_network/core/resource_pools"
)

// PricingStrategy defines the interface for dynamic pricing algorithms
type PricingStrategy interface {
    CalculatePrice(resourceID string, demand, supply, basePrice float64) (float64, error)
}

// DynamicPricingAlgorithm implements dynamic pricing logic
type DynamicPricingAlgorithm struct {
    strategies map[string]PricingStrategy
}

// NewDynamicPricingAlgorithm initializes the dynamic pricing algorithm system
func NewDynamicPricingAlgorithm() *DynamicPricingAlgorithm {
    return &DynamicPricingAlgorithm{
        strategies: make(map[string]PricingStrategy),
    }
}

// RegisterStrategy registers a new pricing strategy
func (dpa *DynamicPricingAlgorithm) RegisterStrategy(name string, strategy PricingStrategy) {
    dpa.strategies[name] = strategy
    log.Printf("Registered pricing strategy: %s", name)
}

// SetPrice adjusts the price of a resource based on the selected strategy
func (dpa *DynamicPricingAlgorithm) SetPrice(resourceID, strategyName string, demand, supply, basePrice float64) (float64, error) {
    strategy, exists := dpa.strategies[strategyName]
    if !exists {
        return 0, fmt.Errorf("pricing strategy not found")
    }
    newPrice, err := strategy.CalculatePrice(resourceID, demand, supply, basePrice)
    if err != nil {
        return 0, err
    }

    // Log and secure the new price
    auditing.LogPriceChange(resourceID, newPrice, time.Now())
    resource_security.SecurePriceData(resourceID, newPrice)
    return newPrice, nil
}

// SupplyDemandStrategy adjusts prices based on supply and demand
type SupplyDemandStrategy struct{}

func (sds *SupplyDemandStrategy) CalculatePrice(resourceID string, demand, supply, basePrice float64) (float64, error) {
    if supply == 0 {
        return 0, fmt.Errorf("supply cannot be zero")
    }
    price := basePrice * (demand / supply)
    return math.Max(price, 0.01), nil // Ensure price is never below a minimum threshold
}

// HistoricalTrendStrategy adjusts prices based on historical trends
type HistoricalTrendStrategy struct {
    history map[string][]float64 // Stores historical price data
}

func NewHistoricalTrendStrategy() *HistoricalTrendStrategy {
    return &HistoricalTrendStrategy{
        history: make(map[string][]float64),
    }
}

func (hts *HistoricalTrendStrategy) CalculatePrice(resourceID string, demand, supply, basePrice float64) (float64, error) {
    trendData, exists := hts.history[resourceID]
    if !exists {
        trendData = []float64{basePrice}
    }

    averageTrend := calculateAverage(trendData)
    newPrice := basePrice * (1 + (averageTrend / 100))

    // Update history with the new price
    trendData = append(trendData, newPrice)
    hts.history[resourceID] = trendData

    return newPrice, nil
}

func calculateAverage(data []float64) float64 {
    sum := 0.0
    for _, value := range data {
        sum += value
    }
    return sum / float64(len(data))
}

// Integrate with other modules as needed
// For instance, contracts can be used to enforce pricing changes

func main() {
    // Example of setting up the dynamic pricing system
    dpa := NewDynamicPricingAlgorithm()

    // Register pricing strategies
    dpa.RegisterStrategy("SupplyDemand", &SupplyDemandStrategy{})
    dpa.RegisterStrategy("HistoricalTrend", NewHistoricalTrendStrategy())

    // Example of setting a price
    price, err := dpa.SetPrice("resource1", "SupplyDemand", 120.0, 100.0, 10.0)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("New price for resource1: %f", price)
}
