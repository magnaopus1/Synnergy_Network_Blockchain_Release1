package assets

import (
	"errors"
	"fmt"
	"math/rand"
	"time"
)

// AssetValuation represents the valuation details of an asset.
type AssetValuation struct {
	ID                string
	CurrentValue      float64
	LastUpdated       time.Time
	HistoricalRecords []HistoricalValuation
}

// HistoricalValuation records the valuation history of an asset.
type HistoricalValuation struct {
	Value     float64
	Timestamp time.Time
}

// ValuationManager handles the operations related to asset valuation.
type ValuationManager struct {
	Valuations map[string]*AssetValuation
}

// NewValuationManager initializes a new ValuationManager.
func NewValuationManager() *ValuationManager {
	return &ValuationManager{
		Valuations: make(map[string]*AssetValuation),
	}
}

// AddValuation adds a new valuation entry for an asset.
func (vm *ValuationManager) AddValuation(id string, initialValue float64) (*AssetValuation, error) {
	if _, exists := vm.Valuations[id]; exists {
		return nil, fmt.Errorf("valuation for asset ID %s already exists", id)
	}
	valuation := &AssetValuation{
		ID:           id,
		CurrentValue: initialValue,
		LastUpdated:  time.Now(),
		HistoricalRecords: []HistoricalValuation{
			{Value: initialValue, Timestamp: time.Now()},
		},
	}
	vm.Valuations[id] = valuation
	return valuation, nil
}

// UpdateValuation updates the valuation of an asset.
func (vm *ValuationManager) UpdateValuation(id string, newValue float64) (*AssetValuation, error) {
	valuation, exists := vm.Valuations[id]
	if !exists {
		return nil, fmt.Errorf("valuation for asset ID %s not found", id)
	}
	valuation.CurrentValue = newValue
	valuation.LastUpdated = time.Now()
	valuation.HistoricalRecords = append(valuation.HistoricalRecords, HistoricalValuation{
		Value:     newValue,
		Timestamp: time.Now(),
	})
	return valuation, nil
}

// GetValuation retrieves the current valuation of an asset.
func (vm *ValuationManager) GetValuation(id string) (*AssetValuation, error) {
	valuation, exists := vm.Valuations[id]
	if !exists {
		return nil, fmt.Errorf("valuation for asset ID %s not found", id)
	}
	return valuation, nil
}

// GetHistoricalValuations retrieves the historical valuation records of an asset.
func (vm *ValuationManager) GetHistoricalValuations(id string) ([]HistoricalValuation, error) {
	valuation, exists := vm.Valuations[id]
	if !exists {
		return nil, fmt.Errorf("valuation for asset ID %s not found", id)
	}
	return valuation.HistoricalRecords, nil
}

// DynamicValuationAlgorithm represents an algorithm for dynamically adjusting asset valuations.
type DynamicValuationAlgorithm struct {
	MarketTrends  float64
	DemandMetrics float64
	UsageMetrics  float64
}

// NewDynamicValuationAlgorithm initializes a new DynamicValuationAlgorithm.
func NewDynamicValuationAlgorithm(marketTrends, demandMetrics, usageMetrics float64) *DynamicValuationAlgorithm {
	return &DynamicValuationAlgorithm{
		MarketTrends:  marketTrends,
		DemandMetrics: demandMetrics,
		UsageMetrics:  usageMetrics,
	}
}

// CalculateNewValuation calculates a new valuation based on market trends, demand, and usage metrics.
func (dva *DynamicValuationAlgorithm) CalculateNewValuation(currentValue float64) float64 {
	// Example algorithm for dynamic valuation calculation
	fluctuation := (dva.MarketTrends + dva.DemandMetrics + dva.UsageMetrics) * (0.01 + rand.Float64()*(0.05-0.01))
	return currentValue * (1 + fluctuation)
}

// ManualAdjustment allows authorized entities to manually adjust the valuation.
func (vm *ValuationManager) ManualAdjustment(id string, newValue float64, authorized bool) error {
	if !authorized {
		return errors.New("unauthorized manual adjustment")
	}
	_, err := vm.UpdateValuation(id, newValue)
	return err
}

// ApplyDynamicValuation applies the dynamic valuation algorithm to update the asset's value.
func (vm *ValuationManager) ApplyDynamicValuation(id string, algorithm *DynamicValuationAlgorithm) (*AssetValuation, error) {
	valuation, err := vm.GetValuation(id)
	if err != nil {
		return nil, err
	}

	newValue := algorithm.CalculateNewValuation(valuation.CurrentValue)
	return vm.UpdateValuation(id, newValue)
}

// AnalyzeHistoricalData provides analysis tools for stakeholders to make informed decisions.
func (vm *ValuationManager) AnalyzeHistoricalData(id string) (map[string]float64, error) {
	historicalData, err := vm.GetHistoricalValuations(id)
	if err != nil {
		return nil, err
	}

	// Example analysis: calculate average, min, max values
	var sum, min, max float64
	count := len(historicalData)

	if count == 0 {
		return nil, errors.New("no historical data available")
	}

	min = historicalData[0].Value
	max = historicalData[0].Value

	for _, record := range historicalData {
		sum += record.Value
		if record.Value < min {
			min = record.Value
		}
		if record.Value > max {
			max = record.Value
		}
	}

	average := sum / float64(count)

	return map[string]float64{
		"average": average,
		"min":     min,
		"max":     max,
	}, nil
}
