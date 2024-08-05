package assets

import (
	"encoding/json"
	"errors"
	"time"
	"sync"
	"github.com/synnergy_network/core/security"
	"github.com/synnergy_network/core/storage"
)

// Collateral represents the collateral information for an asset
type Collateral struct {
	CollateralID    string    `json:"collateral_id"`
	AssetID         string    `json:"asset_id"`
	OwnerID         string    `json:"owner_id"`
	Value           float64   `json:"value"`
	Status          string    `json:"status"`
	CreationDate    time.Time `json:"creation_date"`
	LastUpdatedDate time.Time `json:"last_updated_date"`
}

var (
	collateralStore = make(map[string]Collateral)
	collateralMutex = &sync.Mutex{}
)

// CreateCollateral creates a new collateral record
func CreateCollateral(assetID, ownerID string, value float64, status string) (string, error) {
	collateralMutex.Lock()
	defer collateralMutex.Unlock()

	collateralID := generateCollateralID()
	creationDate := time.Now()

	collateral := Collateral{
		CollateralID:    collateralID,
		AssetID:         assetID,
		OwnerID:         ownerID,
		Value:           value,
		Status:          status,
		CreationDate:    creationDate,
		LastUpdatedDate: creationDate,
	}

	collateralStore[collateralID] = collateral
	err := saveCollateralToStorage(collateral)
	if err != nil {
		return "", err
	}

	return collateralID, nil
}

// UpdateCollateral updates an existing collateral record
func UpdateCollateral(collateralID, assetID, ownerID string, value float64, status string) error {
	collateralMutex.Lock()
	defer collateralMutex.Unlock()

	collateral, exists := collateralStore[collateralID]
	if !exists {
		return errors.New("collateral not found")
	}

	collateral.AssetID = assetID
	collateral.OwnerID = ownerID
	collateral.Value = value
	collateral.Status = status
	collateral.LastUpdatedDate = time.Now()

	collateralStore[collateralID] = collateral
	err := saveCollateralToStorage(collateral)
	if err != nil {
		return err
	}

	return nil
}

// GetCollateral retrieves a collateral record by collateral ID
func GetCollateral(collateralID string) (Collateral, error) {
	collateralMutex.Lock()
	defer collateralMutex.Unlock()

	collateral, exists := collateralStore[collateralID]
	if !exists {
		return Collateral{}, errors.New("collateral not found")
	}

	return collateral, nil
}

// DeleteCollateral deletes a collateral record by collateral ID
func DeleteCollateral(collateralID string) error {
	collateralMutex.Lock()
	defer collateralMutex.Unlock()

	_, exists := collateralStore[collateralID]
	if !exists {
		return errors.New("collateral not found")
	}

	delete(collateralStore, collateralID)
	return deleteCollateralFromStorage(collateralID)
}

// generateCollateralID generates a unique ID for the collateral record
func generateCollateralID() string {
	// Implement unique ID generation logic, for example using UUID
	return "unique-collateral-id"
}

// saveCollateralToStorage securely stores collateral data
func saveCollateralToStorage(collateral Collateral) error {
	data, err := json.Marshal(collateral)
	if err != nil {
		return err
	}

	encryptedData, err := security.Encrypt(data)
	if err != nil {
		return err
	}

	return storage.Save("collateral", collateral.CollateralID, encryptedData)
}

// deleteCollateralFromStorage deletes collateral data from storage
func deleteCollateralFromStorage(collateralID string) error {
	return storage.Delete("collateral", collateralID)
}
