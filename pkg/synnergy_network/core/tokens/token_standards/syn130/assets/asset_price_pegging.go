package assets

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/core/storage"
	"github.com/synnergy_network/utils"
)

// PeggedAsset represents the structure of an asset with pegged price
type PeggedAsset struct {
	AssetID         string
	CurrentPrice    float64
	PeggedIndex     string
	PeggedValue     float64
	LastUpdated     time.Time
	CustomAdjustments map[string]float64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// PricePeggingManager handles pegging price operations for assets
type PricePeggingManager struct {
	PeggedAssets map[string]PeggedAsset
	Mutex        sync.Mutex
}

// NewPricePeggingManager creates a new instance of PricePeggingManager
func NewPricePeggingManager() *PricePeggingManager {
	return &PricePeggingManager{
		PeggedAssets: make(map[string]PeggedAsset),
	}
}

// AddPeggedAsset adds a new pegged asset
func (ppm *PricePeggingManager) AddPeggedAsset(assetID, peggedIndex string, peggedValue float64) error {
	ppm.Mutex.Lock()
	defer ppm.Mutex.Unlock()

	if _, exists := ppm.PeggedAssets[assetID]; exists {
		return errors.New("pegged asset already exists")
	}

	ppm.PeggedAssets[assetID] = PeggedAsset{
		AssetID:      assetID,
		PeggedIndex:  peggedIndex,
		PeggedValue:  peggedValue,
		LastUpdated:  time.Now(),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	return nil
}

// UpdatePeggedAsset updates the pegged asset's pegged value and adjustments
func (ppm *PricePeggingManager) UpdatePeggedAsset(assetID, peggedIndex string, peggedValue float64, customAdjustments map[string]float64) error {
	ppm.Mutex.Lock()
	defer ppm.Mutex.Unlock()

	peggedAsset, exists := ppm.PeggedAssets[assetID]
	if !exists {
		return errors.New("pegged asset not found")
	}

	peggedAsset.PeggedIndex = peggedIndex
	peggedAsset.PeggedValue = peggedValue
	peggedAsset.CustomAdjustments = customAdjustments
	peggedAsset.UpdatedAt = time.Now()
	ppm.PeggedAssets[assetID] = peggedAsset
	return nil
}

// RemovePeggedAsset removes a pegged asset
func (ppm *PricePeggingManager) RemovePeggedAsset(assetID string) error {
	ppm.Mutex.Lock()
	defer ppm.Mutex.Unlock()

	if _, exists := ppm.PeggedAssets[assetID]; !exists {
		return errors.New("pegged asset not found")
	}

	delete(ppm.PeggedAssets, assetID)
	return nil
}

// GetPeggedAsset retrieves a pegged asset by its ID
func (ppm *PricePeggingManager) GetPeggedAsset(assetID string) (PeggedAsset, error) {
	ppm.Mutex.Lock()
	defer ppm.Mutex.Unlock()

	peggedAsset, exists := ppm.PeggedAssets[assetID]
	if !exists {
		return PeggedAsset{}, errors.New("pegged asset not found")
	}
	return peggedAsset, nil
}

// CalculateCurrentPrice calculates the current price of a pegged asset based on the pegged value and custom adjustments
func (ppm *PricePeggingManager) CalculateCurrentPrice(assetID string) (float64, error) {
	ppm.Mutex.Lock()
	defer ppm.Mutex.Unlock()

	peggedAsset, exists := ppm.PeggedAssets[assetID]
	if !exists {
		return 0, errors.New("pegged asset not found")
	}

	currentPrice := peggedAsset.PeggedValue
	for _, adjustment := range peggedAsset.CustomAdjustments {
		currentPrice += adjustment
	}

	peggedAsset.CurrentPrice = currentPrice
	peggedAsset.LastUpdated = time.Now()
	ppm.PeggedAssets[assetID] = peggedAsset

	return currentPrice, nil
}

// SavePeggedAssets saves the pegged assets to persistent storage
func (ppm *PricePeggingManager) SavePeggedAssets(storagePath string) error {
	ppm.Mutex.Lock()
	defer ppm.Mutex.Unlock()

	data, err := json.Marshal(ppm.PeggedAssets)
	if err != nil {
		return err
	}
	return storage.Save(storagePath, data)
}

// LoadPeggedAssets loads the pegged assets from persistent storage
func (ppm *PricePeggingManager) LoadPeggedAssets(storagePath string) error {
	ppm.Mutex.Lock()
	defer ppm.Mutex.Unlock()

	data, err := storage.Load(storagePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &ppm.PeggedAssets)
	if err != nil {
		return err
	}
	return nil
}
