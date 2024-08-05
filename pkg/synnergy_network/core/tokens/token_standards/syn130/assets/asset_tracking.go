package assets

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/synnergy_network/core/storage"
	"github.com/synnergy_network/utils"
)

// AssetStatus represents the status of an asset
type AssetStatus struct {
	Condition   string
	Location    string
	LastUpdated time.Time
	Metadata    map[string]string
}

// TrackedAsset represents a structure for a tracked asset
type TrackedAsset struct {
	AssetID     string
	Status      AssetStatus
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// AssetTrackingManager handles tracking of assets
type AssetTrackingManager struct {
	TrackedAssets map[string]TrackedAsset
	Mutex         sync.Mutex
}

// NewAssetTrackingManager creates a new instance of AssetTrackingManager
func NewAssetTrackingManager() *AssetTrackingManager {
	return &AssetTrackingManager{
		TrackedAssets: make(map[string]TrackedAsset),
	}
}

// AddTrackedAsset adds a new asset to be tracked
func (atm *AssetTrackingManager) AddTrackedAsset(assetID, condition, location string, metadata map[string]string) error {
	atm.Mutex.Lock()
	defer atm.Mutex.Unlock()

	if _, exists := atm.TrackedAssets[assetID]; exists {
		return errors.New("tracked asset already exists")
	}

	atm.TrackedAssets[assetID] = TrackedAsset{
		AssetID: assetID,
		Status: AssetStatus{
			Condition:   condition,
			Location:    location,
			LastUpdated: time.Now(),
			Metadata:    metadata,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	return nil
}

// UpdateTrackedAsset updates the status of a tracked asset
func (atm *AssetTrackingManager) UpdateTrackedAsset(assetID, condition, location string, metadata map[string]string) error {
	atm.Mutex.Lock()
	defer atm.Mutex.Unlock()

	trackedAsset, exists := atm.TrackedAssets[assetID]
	if !exists {
		return errors.New("tracked asset not found")
	}

	trackedAsset.Status = AssetStatus{
		Condition:   condition,
		Location:    location,
		LastUpdated: time.Now(),
		Metadata:    metadata,
	}
	trackedAsset.UpdatedAt = time.Now()
	atm.TrackedAssets[assetID] = trackedAsset
	return nil
}

// RemoveTrackedAsset removes a tracked asset
func (atm *AssetTrackingManager) RemoveTrackedAsset(assetID string) error {
	atm.Mutex.Lock()
	defer atm.Mutex.Unlock()

	if _, exists := atm.TrackedAssets[assetID]; !exists {
		return errors.New("tracked asset not found")
	}

	delete(atm.TrackedAssets, assetID)
	return nil
}

// GetTrackedAsset retrieves the status of a tracked asset
func (atm *AssetTrackingManager) GetTrackedAsset(assetID string) (TrackedAsset, error) {
	atm.Mutex.Lock()
	defer atm.Mutex.Unlock()

	trackedAsset, exists := atm.TrackedAssets[assetID]
	if !exists {
		return TrackedAsset{}, errors.New("tracked asset not found")
	}
	return trackedAsset, nil
}

// SaveTrackedAssets saves the tracked assets to persistent storage
func (atm *AssetTrackingManager) SaveTrackedAssets(storagePath string) error {
	atm.Mutex.Lock()
	defer atm.Mutex.Unlock()

	data, err := json.Marshal(atm.TrackedAssets)
	if err != nil {
		return err
	}
	return storage.Save(storagePath, data)
}

// LoadTrackedAssets loads the tracked assets from persistent storage
func (atm *AssetTrackingManager) LoadTrackedAssets(storagePath string) error {
	atm.Mutex.Lock()
	defer atm.Mutex.Unlock()

	data, err := storage.Load(storagePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &atm.TrackedAssets)
	if err != nil {
		return err
	}
	return nil
}

// GenerateAssetReport generates a report for a specific asset
func (atm *AssetTrackingManager) GenerateAssetReport(assetID string) (string, error) {
	trackedAsset, err := atm.GetTrackedAsset(assetID)
	if err != nil {
		return "", err
	}

	report := struct {
		AssetID   string
		Status    AssetStatus
		CreatedAt time.Time
		UpdatedAt time.Time
	}{
		AssetID:   trackedAsset.AssetID,
		Status:    trackedAsset.Status,
		CreatedAt: trackedAsset.CreatedAt,
		UpdatedAt: trackedAsset.UpdatedAt,
	}

	reportJSON, err := json.Marshal(report)
	if err != nil {
		return "", err
	}

	return string(reportJSON), nil
}

// MonitorAssetWithIoT integrates IoT devices for real-time monitoring
func (atm *AssetTrackingManager) MonitorAssetWithIoT(assetID string, sensorData map[string]string) error {
	atm.Mutex.Lock()
	defer atm.Mutex.Unlock()

	trackedAsset, exists := atm.TrackedAssets[assetID]
	if !exists {
		return errors.New("tracked asset not found")
	}

	for key, value := range sensorData {
		trackedAsset.Status.Metadata[key] = value
	}
	trackedAsset.Status.LastUpdated = time.Now()
	trackedAsset.UpdatedAt = time.Now()
	atm.TrackedAssets[assetID] = trackedAsset

	return nil
}
