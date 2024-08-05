package peg

import (
	"log"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/crypto"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/util"
)

// MaintenanceService represents a service for maintaining the peg system.
type MaintenanceService struct {
	assets          map[string]*Asset
	mutex           sync.Mutex
	logger          *log.Logger
	notificationSvc NotificationService
}

// Asset represents an asset in the peg system.
type Asset struct {
	ID            string
	Value         float64
	LastMaintenance time.Time
}

// NotificationService represents a service for sending notifications.
type NotificationService interface {
	SendNotification(message string) error
}

// NewMaintenanceService creates a new instance of MaintenanceService.
func NewMaintenanceService(logger *log.Logger, notificationSvc NotificationService) *MaintenanceService {
	return &MaintenanceService{
		assets:          make(map[string]*Asset),
		logger:          logger,
		notificationSvc: notificationSvc,
	}
}

// AddAsset adds a new asset to the maintenance service.
func (ms *MaintenanceService) AddAsset(assetID string, initialValue float64) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	if _, exists := ms.assets[assetID]; exists {
		return errors.New("asset already exists")
	}

	asset := &Asset{
		ID:              assetID,
		Value:           initialValue,
		LastMaintenance: time.Now(),
	}

	ms.assets[assetID] = asset
	ms.logger.Println("New asset added:", assetID)
	return nil
}

// RemoveAsset removes an asset from the maintenance service.
func (ms *MaintenanceService) RemoveAsset(assetID string) error {
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
func (ms *MaintenanceService) GetAssetValue(assetID string) (float64, error) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	asset, exists := ms.assets[assetID]
	if !exists {
		return 0, errors.New("asset not found")
	}

	return asset.Value, nil
}

// PerformMaintenance performs maintenance on an asset.
func (ms *MaintenanceService) PerformMaintenance(assetID string) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	asset, exists := ms.assets[assetID]
	if !exists {
		return errors.New("asset not found")
	}

	// Simulate maintenance operation
	asset.LastMaintenance = time.Now()
	ms.logger.Println("Maintenance performed on asset:", assetID)

	err := ms.notificationSvc.SendNotification("Maintenance performed on asset: " + assetID)
	if err != nil {
		ms.logger.Println("Failed to send notification for asset maintenance:", assetID, err)
	}

	return nil
}

// ScheduleMaintenance schedules maintenance for all assets at a given interval.
func (ms *MaintenanceService) ScheduleMaintenance(interval time.Duration) {
	for {
		time.Sleep(interval)
		ms.mutex.Lock()
		for assetID := range ms.assets {
			ms.mutex.Unlock()
			err := ms.PerformMaintenance(assetID)
			if err != nil {
				ms.logger.Println("Failed to perform maintenance on asset:", assetID, err)
			}
			ms.mutex.Lock()
		}
		ms.mutex.Unlock()
	}
}

// EncryptAssetData encrypts the asset data.
func (ms *MaintenanceService) EncryptAssetData(assetID string, data []byte) ([]byte, error) {
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
func (ms *MaintenanceService) DecryptAssetData(assetID string, encryptedData []byte) ([]byte, error) {
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
func (ms *MaintenanceService) BackupAssets() (map[string]*Asset, error) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	backup := make(map[string]*Asset)
	for id, asset := range ms.assets {
		backup[id] = &Asset{
			ID:              asset.ID,
			Value:           asset.Value,
			LastMaintenance: asset.LastMaintenance,
		}
	}

	ms.logger.Println("Assets backup created")
	return backup, nil
}

// RestoreAssets restores assets from a backup.
func (ms *MaintenanceService) RestoreAssets(backup map[string]*Asset) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	for id, asset := range backup {
		ms.assets[id] = &Asset{
			ID:              asset.ID,
			Value:           asset.Value,
			LastMaintenance: asset.LastMaintenance,
		}
	}

	ms.logger.Println("Assets restored from backup")
	return nil
}
