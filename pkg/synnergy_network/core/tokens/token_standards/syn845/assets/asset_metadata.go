package assets

import (
	"encoding/json"
	"errors"
	"time"
	"sync"
	"github.com/synnergy_network/core/security"
	"github.com/synnergy_network/core/storage"
)

// AssetMetadata represents the metadata of an asset associated with a debt instrument
type AssetMetadata struct {
	AssetID          string    `json:"asset_id"`
	OwnerID          string    `json:"owner_id"`
	Description      string    `json:"description"`
	CreationDate     time.Time `json:"creation_date"`
	LastUpdatedDate  time.Time `json:"last_updated_date"`
	Value            float64   `json:"value"`
	CollateralStatus string    `json:"collateral_status"`
}

var (
	assetMetadataStore = make(map[string]AssetMetadata)
	mutex              = &sync.Mutex{}
)

// CreateAssetMetadata creates a new asset metadata entry and stores it securely
func CreateAssetMetadata(ownerID, description string, value float64, collateralStatus string) (string, error) {
	mutex.Lock()
	defer mutex.Unlock()

	assetID := generateAssetID()
	creationDate := time.Now()

	assetMetadata := AssetMetadata{
		AssetID:          assetID,
		OwnerID:          ownerID,
		Description:      description,
		CreationDate:     creationDate,
		LastUpdatedDate:  creationDate,
		Value:            value,
		CollateralStatus: collateralStatus,
	}

	assetMetadataStore[assetID] = assetMetadata
	err := saveAssetMetadataToStorage(assetMetadata)
	if err != nil {
		return "", err
	}

	return assetID, nil
}

// UpdateAssetMetadata updates an existing asset metadata entry
func UpdateAssetMetadata(assetID, ownerID, description string, value float64, collateralStatus string) error {
	mutex.Lock()
	defer mutex.Unlock()

	assetMetadata, exists := assetMetadataStore[assetID]
	if !exists {
		return errors.New("asset metadata not found")
	}

	assetMetadata.OwnerID = ownerID
	assetMetadata.Description = description
	assetMetadata.LastUpdatedDate = time.Now()
	assetMetadata.Value = value
	assetMetadata.CollateralStatus = collateralStatus

	assetMetadataStore[assetID] = assetMetadata
	err := saveAssetMetadataToStorage(assetMetadata)
	if err != nil {
		return err
	}

	return nil
}

// GetAssetMetadata retrieves asset metadata by asset ID
func GetAssetMetadata(assetID string) (AssetMetadata, error) {
	mutex.Lock()
	defer mutex.Unlock()

	assetMetadata, exists := assetMetadataStore[assetID]
	if !exists {
		return AssetMetadata{}, errors.New("asset metadata not found")
	}

	return assetMetadata, nil
}

// DeleteAssetMetadata removes asset metadata by asset ID
func DeleteAssetMetadata(assetID string) error {
	mutex.Lock()
	defer mutex.Unlock()

	_, exists := assetMetadataStore[assetID]
	if !exists {
		return errors.New("asset metadata not found")
	}

	delete(assetMetadataStore, assetID)
	return deleteAssetMetadataFromStorage(assetID)
}

// generateAssetID generates a unique ID for the asset
func generateAssetID() string {
	// Implement unique ID generation logic, for example using UUID
	return "unique-asset-id"
}

// saveAssetMetadataToStorage securely stores asset metadata
func saveAssetMetadataToStorage(assetMetadata AssetMetadata) error {
	data, err := json.Marshal(assetMetadata)
	if err != nil {
		return err
	}

	encryptedData, err := security.Encrypt(data)
	if err != nil {
		return err
	}

	return storage.Save("assetMetadata", assetMetadata.AssetID, encryptedData)
}

// deleteAssetMetadataFromStorage deletes asset metadata from storage
func deleteAssetMetadataFromStorage(assetID string) error {
	return storage.Delete("assetMetadata", assetID)
}
