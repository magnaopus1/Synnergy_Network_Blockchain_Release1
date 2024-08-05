package assets

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/core/storage"
	"github.com/synnergy_network/utils"
)

// AssetValuationManager handles valuation of assets
type AssetValuationManager struct {
	AssetValuations map[string]AssetValuation
	Mutex           sync.Mutex
}

// AssetValuation represents the valuation details of an asset
type AssetValuation struct {
	AssetID         string
	CurrentValue    float64
	ValuationMethod string
	ValuationDate   time.Time
	ValuationHistory []ValuationHistoryEntry
}

// ValuationHistoryEntry represents a single valuation record
type ValuationHistoryEntry struct {
	Value         float64
	Method        string
	Adjustment    float64
	Timestamp     time.Time
	ContextualData map[string]string
}

// NewAssetValuationManager creates a new instance of AssetValuationManager
func NewAssetValuationManager() *AssetValuationManager {
	return &AssetValuationManager{
		AssetValuations: make(map[string]AssetValuation),
	}
}

// AddAssetValuation adds a new valuation record for an asset
func (avm *AssetValuationManager) AddAssetValuation(assetID string, value float64, method string, contextualData map[string]string) error {
	avm.Mutex.Lock()
	defer avm.Mutex.Unlock()

	if _, exists := avm.AssetValuations[assetID]; exists {
		return errors.New("valuation for asset already exists")
	}

	avm.AssetValuations[assetID] = AssetValuation{
		AssetID:      assetID,
		CurrentValue: value,
		ValuationMethod: method,
		ValuationDate:   time.Now(),
		ValuationHistory: []ValuationHistoryEntry{
			{
				Value:         value,
				Method:        method,
				Adjustment:    0,
				Timestamp:     time.Now(),
				ContextualData: contextualData,
			},
		},
	}
	return nil
}

// UpdateAssetValuation updates the valuation of an asset
func (avm *AssetValuationManager) UpdateAssetValuation(assetID string, newValue float64, method string, adjustment float64, contextualData map[string]string) error {
	avm.Mutex.Lock()
	defer avm.Mutex.Unlock()

	assetValuation, exists := avm.AssetValuations[assetID]
	if !exists {
		return errors.New("valuation for asset not found")
	}

	assetValuation.CurrentValue = newValue
	assetValuation.ValuationMethod = method
	assetValuation.ValuationDate = time.Now()
	assetValuation.ValuationHistory = append(assetValuation.ValuationHistory, ValuationHistoryEntry{
		Value:         newValue,
		Method:        method,
		Adjustment:    adjustment,
		Timestamp:     time.Now(),
		ContextualData: contextualData,
	})
	avm.AssetValuations[assetID] = assetValuation
	return nil
}

// GetAssetValuation retrieves the current valuation of an asset
func (avm *AssetValuationManager) GetAssetValuation(assetID string) (AssetValuation, error) {
	avm.Mutex.Lock()
	defer avm.Mutex.Unlock()

	assetValuation, exists := avm.AssetValuations[assetID]
	if !exists {
		return AssetValuation{}, errors.New("valuation for asset not found")
	}
	return assetValuation, nil
}

// GetAssetValuationHistory retrieves the valuation history of an asset
func (avm *AssetValuationManager) GetAssetValuationHistory(assetID string) ([]ValuationHistoryEntry, error) {
	avm.Mutex.Lock()
	defer avm.Mutex.Unlock()

	assetValuation, exists := avm.AssetValuations[assetID]
	if !exists {
		return nil, errors.New("valuation for asset not found")
	}
	return assetValuation.ValuationHistory, nil
}

// SaveAssetValuations saves the asset valuations to persistent storage
func (avm *AssetValuationManager) SaveAssetValuations(storagePath string) error {
	avm.Mutex.Lock()
	defer avm.Mutex.Unlock()

	data, err := json.Marshal(avm.AssetValuations)
	if err != nil {
		return err
	}
	return storage.Save(storagePath, data)
}

// LoadAssetValuations loads the asset valuations from persistent storage
func (avm *AssetValuationManager) LoadAssetValuations(storagePath string) error {
	avm.Mutex.Lock()
	defer avm.Mutex.Unlock()

	data, err := storage.Load(storagePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &avm.AssetValuations)
	if err != nil {
		return err
	}
	return nil
}

// GenerateValuationReport generates a valuation report for a specific asset
func (avm *AssetValuationManager) GenerateValuationReport(assetID string) (string, error) {
	assetValuation, err := avm.GetAssetValuation(assetID)
	if err != nil {
		return "", err
	}

	report := struct {
		AssetID         string
		CurrentValue    float64
		ValuationMethod string
		ValuationDate   time.Time
		ValuationHistory []ValuationHistoryEntry
	}{
		AssetID:          assetValuation.AssetID,
		CurrentValue:     assetValuation.CurrentValue,
		ValuationMethod:  assetValuation.ValuationMethod,
		ValuationDate:    assetValuation.ValuationDate,
		ValuationHistory: assetValuation.ValuationHistory,
	}

	reportJSON, err := json.Marshal(report)
	if err != nil {
		return "", err
	}

	return string(reportJSON), nil
}

// ApplyManualAdjustment allows certified appraisers to manually adjust the valuation of an asset
func (avm *AssetValuationManager) ApplyManualAdjustment(assetID string, adjustment float64, appraiserID string, notes string) error {
	avm.Mutex.Lock()
	defer avm.Mutex.Unlock()

	assetValuation, exists := avm.AssetValuations[assetID]
	if !exists {
		return errors.New("valuation for asset not found")
	}

	newValue := assetValuation.CurrentValue + adjustment
	assetValuation.CurrentValue = newValue
	assetValuation.ValuationDate = time.Now()
	assetValuation.ValuationHistory = append(assetValuation.ValuationHistory, ValuationHistoryEntry{
		Value:         newValue,
		Method:        "manual",
		Adjustment:    adjustment,
		Timestamp:     time.Now(),
		ContextualData: map[string]string{"appraiser_id": appraiserID, "notes": notes},
	})
	avm.AssetValuations[assetID] = assetValuation
	return nil
}

// IntegrateRealTimeData integrates real-time data sources for dynamic value adjustment
func (avm *AssetValuationManager) IntegrateRealTimeData(assetID string, dataSources map[string]float64) error {
	avm.Mutex.Lock()
	defer avm.Mutex.Unlock()

	assetValuation, exists := avm.AssetValuations[assetID]
	if !exists {
		return errors.New("valuation for asset not found")
	}

	// Example: Averaging data from multiple sources for dynamic adjustment
	totalValue := assetValuation.CurrentValue
	for _, value := range dataSources {
		totalValue += value
	}
	newValue := totalValue / float64(len(dataSources)+1)

	assetValuation.CurrentValue = newValue
	assetValuation.ValuationDate = time.Now()
	assetValuation.ValuationHistory = append(assetValuation.ValuationHistory, ValuationHistoryEntry{
		Value:         newValue,
		Method:        "real-time",
		Adjustment:    newValue - assetValuation.CurrentValue,
		Timestamp:     time.Now(),
		ContextualData: map[string]string{"data_sources": utils.MapToString(dataSources)},
	})
	avm.AssetValuations[assetID] = assetValuation
	return nil
}
