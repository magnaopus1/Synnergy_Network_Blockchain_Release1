package assets

import (
	"encoding/json"
	"errors"
	"time"
	"sync"
	"github.com/synnergy_network/core/security"
	"github.com/synnergy_network/core/storage"
)

// AssetValuation represents the valuation information for an asset
type AssetValuation struct {
	ValuationID     string    `json:"valuation_id"`
	AssetID         string    `json:"asset_id"`
	ValuationAmount float64   `json:"valuation_amount"`
	ValuationDate   time.Time `json:"valuation_date"`
	LastUpdatedDate time.Time `json:"last_updated_date"`
}

var (
	assetValuationStore = make(map[string]AssetValuation)
	valuationMutex      = &sync.Mutex{}
)

// CreateAssetValuation creates a new asset valuation record
func CreateAssetValuation(assetID string, valuationAmount float64) (string, error) {
	valuationMutex.Lock()
	defer valuationMutex.Unlock()

	valuationID := generateValuationID()
	valuationDate := time.Now()

	assetValuation := AssetValuation{
		ValuationID:     valuationID,
		AssetID:         assetID,
		ValuationAmount: valuationAmount,
		ValuationDate:   valuationDate,
		LastUpdatedDate: valuationDate,
	}

	assetValuationStore[valuationID] = assetValuation
	err := saveAssetValuationToStorage(assetValuation)
	if err != nil {
		return "", err
	}

	return valuationID, nil
}

// UpdateAssetValuation updates an existing asset valuation record
func UpdateAssetValuation(valuationID, assetID string, valuationAmount float64) error {
	valuationMutex.Lock()
	defer valuationMutex.Unlock()

	assetValuation, exists := assetValuationStore[valuationID]
	if !exists {
		return errors.New("asset valuation not found")
	}

	assetValuation.AssetID = assetID
	assetValuation.ValuationAmount = valuationAmount
	assetValuation.LastUpdatedDate = time.Now()

	assetValuationStore[valuationID] = assetValuation
	err := saveAssetValuationToStorage(assetValuation)
	if err != nil {
		return err
	}

	return nil
}

// GetAssetValuation retrieves an asset valuation record by valuation ID
func GetAssetValuation(valuationID string) (AssetValuation, error) {
	valuationMutex.Lock()
	defer valuationMutex.Unlock()

	assetValuation, exists := assetValuationStore[valuationID]
	if !exists {
		return AssetValuation{}, errors.New("asset valuation not found")
	}

	return assetValuation, nil
}

// DeleteAssetValuation deletes an asset valuation record by valuation ID
func DeleteAssetValuation(valuationID string) error {
	valuationMutex.Lock()
	defer valuationMutex.Unlock()

	_, exists := assetValuationStore[valuationID]
	if !exists {
		return errors.New("asset valuation not found")
	}

	delete(assetValuationStore, valuationID)
	return deleteAssetValuationFromStorage(valuationID)
}

// generateValuationID generates a unique ID for the asset valuation record
func generateValuationID() string {
	// Implement unique ID generation logic, for example using UUID
	return "unique-valuation-id"
}

// saveAssetValuationToStorage securely stores asset valuation data
func saveAssetValuationToStorage(assetValuation AssetValuation) error {
	data, err := json.Marshal(assetValuation)
	if err != nil {
		return err
	}

	encryptedData, err := security.Encrypt(data)
	if err != nil {
		return err
	}

	return storage.Save("assetValuation", assetValuation.ValuationID, encryptedData)
}

// deleteAssetValuationFromStorage deletes asset valuation data from storage
func deleteAssetValuationFromStorage(valuationID string) error {
	return storage.Delete("assetValuation", valuationID)
}
