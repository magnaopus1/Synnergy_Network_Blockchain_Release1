package peg

import (
	"errors"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/crypto"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/util"
)

// MonitoringService represents a service for monitoring the peg system.
type MonitoringService struct {
	assets          map[string]*Asset
	mutex           sync.Mutex
	logger          *log.Logger
	notificationSvc NotificationService
	monitoringFreq  time.Duration
}

// Asset represents an asset in the peg system.
type Asset struct {
	ID              string
	Value           float64
	LastMonitored   time.Time
	HealthStatus    string
}

// NotificationService represents a service for sending notifications.
type NotificationService interface {
	SendNotification(message string) error
}

// NewMonitoringService creates a new instance of MonitoringService.
func NewMonitoringService(logger *log.Logger, notificationSvc NotificationService, freq time.Duration) *MonitoringService {
	return &MonitoringService{
		assets:          make(map[string]*Asset),
		logger:          logger,
		notificationSvc: notificationSvc,
		monitoringFreq:  freq,
	}
}

// AddAsset adds a new asset to the monitoring service.
func (ms *MonitoringService) AddAsset(assetID string, initialValue float64) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	if _, exists := ms.assets[assetID]; exists {
		return errors.New("asset already exists")
	}

	asset := &Asset{
		ID:            assetID,
		Value:         initialValue,
		LastMonitored: time.Now(),
		HealthStatus:  "Healthy",
	}

	ms.assets[assetID] = asset
	ms.logger.Println("New asset added:", assetID)
	return nil
}

// RemoveAsset removes an asset from the monitoring service.
func (ms *MonitoringService) RemoveAsset(assetID string) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	if _, exists := ms.assets[assetID]; !exists {
		return errors.New("asset not found")
	}

	delete(ms.assets, assetID)
	ms.logger.Println("Asset removed:", assetID)
	return nil
}

// GetAssetValue gets the value of an asset.
func (ms *MonitoringService) GetAssetValue(assetID string) (float64, error) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	asset, exists := ms.assets[assetID]
	if !exists {
		return 0, errors.New("asset not found")
	}

	return asset.Value, nil
}

// MonitorAssets monitors the health and status of all assets.
func (ms *MonitoringService) MonitorAssets() {
	for {
		time.Sleep(ms.monitoringFreq)
		ms.mutex.Lock()
		for assetID, asset := range ms.assets {
			ms.mutex.Unlock()
			err := ms.monitorAsset(asset)
			if err != nil {
				ms.logger.Println("Failed to monitor asset:", assetID, err)
			}
			ms.mutex.Lock()
		}
		ms.mutex.Unlock()
	}
}

// monitorAsset monitors the health and status of a single asset.
func (ms *MonitoringService) monitorAsset(asset *Asset) error {
	// Simulate monitoring operation
	asset.LastMonitored = time.Now()
	asset.HealthStatus = "Healthy" // This should be replaced with actual health check logic
	ms.logger.Println("Monitored asset:", asset.ID, "HealthStatus:", asset.HealthStatus)

	err := ms.notificationSvc.SendNotification("Monitored asset: " + asset.ID + " HealthStatus: " + asset.HealthStatus)
	if err != nil {
		ms.logger.Println("Failed to send notification for asset monitoring:", asset.ID, err)
	}

	return nil
}

// EncryptAssetData encrypts the asset data.
func (ms *MonitoringService) EncryptAssetData(assetID string, data []byte) ([]byte, error) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	asset, exists := ms.assets[assetID]
	if !exists {
		return nil, errors.New("asset not found")
	}

	encryptedData, err := crypto.EncryptAES(asset.ID, data)
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}

// DecryptAssetData decrypts the asset data.
func (ms *MonitoringService) DecryptAssetData(assetID string, encryptedData []byte) ([]byte, error) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	asset, exists := ms.assets[assetID]
	if !exists {
		return nil, errors.New("asset not found")
	}

	decryptedData, err := crypto.DecryptAES(asset.ID, encryptedData)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

// BackupAssets creates a backup of all assets.
func (ms *MonitoringService) BackupAssets() (map[string]*Asset, error) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	backup := make(map[string]*Asset)
	for id, asset := range ms.assets {
		backup[id] = &Asset{
			ID:            asset.ID,
			Value:         asset.Value,
			LastMonitored: asset.LastMonitored,
			HealthStatus:  asset.HealthStatus,
		}
	}

	ms.logger.Println("Assets backup created")
	return backup, nil
}

// RestoreAssets restores assets from a backup.
func (ms *MonitoringService) RestoreAssets(backup map[string]*Asset) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	for id, asset := range backup {
		ms.assets[id] = &Asset{
			ID:            asset.ID,
			Value:         asset.Value,
			LastMonitored: asset.LastMonitored,
			HealthStatus:  asset.HealthStatus,
		}
	}

	ms.logger.Println("Assets restored from backup")
	return nil
}
