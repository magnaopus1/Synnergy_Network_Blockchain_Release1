package assets

import (
	"encoding/json"
	"errors"
	"time"
	"sync"
	"github.com/synnergy_network/core/security"
	"github.com/synnergy_network/core/storage"
)

// AssetTracking represents the tracking information for an asset
type AssetTracking struct {
	TrackingID      string    `json:"tracking_id"`
	AssetID         string    `json:"asset_id"`
	CurrentOwnerID  string    `json:"current_owner_id"`
	PreviousOwnerID string    `json:"previous_owner_id"`
	Status          string    `json:"status"`
	LastUpdatedDate time.Time `json:"last_updated_date"`
}

var (
	assetTrackingStore = make(map[string]AssetTracking)
	trackingMutex      = &sync.Mutex{}
)

// CreateAssetTracking creates a new asset tracking record
func CreateAssetTracking(assetID, currentOwnerID, status string) (string, error) {
	trackingMutex.Lock()
	defer trackingMutex.Unlock()

	trackingID := generateTrackingID()
	creationDate := time.Now()

	assetTracking := AssetTracking{
		TrackingID:      trackingID,
		AssetID:         assetID,
		CurrentOwnerID:  currentOwnerID,
		Status:          status,
		LastUpdatedDate: creationDate,
	}

	assetTrackingStore[trackingID] = assetTracking
	err := saveAssetTrackingToStorage(assetTracking)
	if err != nil {
		return "", err
	}

	return trackingID, nil
}

// UpdateAssetTracking updates an existing asset tracking record
func UpdateAssetTracking(trackingID, assetID, currentOwnerID, previousOwnerID, status string) error {
	trackingMutex.Lock()
	defer trackingMutex.Unlock()

	assetTracking, exists := assetTrackingStore[trackingID]
	if !exists {
		return errors.New("asset tracking not found")
	}

	assetTracking.AssetID = assetID
	assetTracking.CurrentOwnerID = currentOwnerID
	assetTracking.PreviousOwnerID = previousOwnerID
	assetTracking.Status = status
	assetTracking.LastUpdatedDate = time.Now()

	assetTrackingStore[trackingID] = assetTracking
	err := saveAssetTrackingToStorage(assetTracking)
	if err != nil {
		return err
	}

	return nil
}

// GetAssetTracking retrieves an asset tracking record by tracking ID
func GetAssetTracking(trackingID string) (AssetTracking, error) {
	trackingMutex.Lock()
	defer trackingMutex.Unlock()

	assetTracking, exists := assetTrackingStore[trackingID]
	if !exists {
		return AssetTracking{}, errors.New("asset tracking not found")
	}

	return assetTracking, nil
}

// DeleteAssetTracking deletes an asset tracking record by tracking ID
func DeleteAssetTracking(trackingID string) error {
	trackingMutex.Lock()
	defer trackingMutex.Unlock()

	_, exists := assetTrackingStore[trackingID]
	if !exists {
		return errors.New("asset tracking not found")
	}

	delete(assetTrackingStore, trackingID)
	return deleteAssetTrackingFromStorage(trackingID)
}

// generateTrackingID generates a unique ID for the asset tracking record
func generateTrackingID() string {
	// Implement unique ID generation logic, for example using UUID
	return "unique-tracking-id"
}

// saveAssetTrackingToStorage securely stores asset tracking data
func saveAssetTrackingToStorage(assetTracking AssetTracking) error {
	data, err := json.Marshal(assetTracking)
	if err != nil {
		return err
	}

	encryptedData, err := security.Encrypt(data)
	if err != nil {
		return err
	}

	return storage.Save("assetTracking", assetTracking.TrackingID, encryptedData)
}

// deleteAssetTrackingFromStorage deletes asset tracking data from storage
func deleteAssetTrackingFromStorage(trackingID string) error {
	return storage.Delete("assetTracking", trackingID)
}
