package peg

import (
	"errors"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/crypto"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/util"
)

// DynamicAdjustment handles the dynamic adjustments of the peg system.
type DynamicAdjustment struct {
	assets          map[string]*Asset
	mutex           sync.Mutex
	logger          *log.Logger
	adjustmentAlgo  AdjustmentAlgorithm
	priceFeed       PriceFeed
	notificationSvc NotificationService
}

// Asset represents an asset in the peg system.
type Asset struct {
	ID            string
	Value         float64
	LastAdjustment time.Time
}

// AdjustmentAlgorithm represents the algorithm used for dynamic adjustment.
type AdjustmentAlgorithm interface {
	CalculateNewValue(currentValue, marketPrice float64) (float64, error)
}

// PriceFeed represents a service that provides market prices.
type PriceFeed interface {
	GetMarketPrice(assetID string) (float64, error)
}

// NotificationService represents a service for sending notifications.
type NotificationService interface {
	SendNotification(message string) error
}

// NewDynamicAdjustment creates a new instance of DynamicAdjustment.
func NewDynamicAdjustment(logger *log.Logger, adjustmentAlgo AdjustmentAlgorithm, priceFeed PriceFeed, notificationSvc NotificationService) *DynamicAdjustment {
	return &DynamicAdjustment{
		assets:          make(map[string]*Asset),
		logger:          logger,
		adjustmentAlgo:  adjustmentAlgo,
		priceFeed:       priceFeed,
		notificationSvc: notificationSvc,
	}
}

// AddAsset adds a new asset to the peg system.
func (da *DynamicAdjustment) AddAsset(assetID string, initialValue float64) error {
	da.mutex.Lock()
	defer da.mutex.Unlock()

	if _, exists := da.assets[assetID]; exists {
		return errors.New("asset already exists")
	}

	asset := &Asset{
		ID:            assetID,
		Value:         initialValue,
		LastAdjustment: time.Now(),
	}

	da.assets[assetID] = asset
	da.logger.Println("New asset added:", assetID)
	return nil
}

// RemoveAsset removes an asset from the peg system.
func (da *DynamicAdjustment) RemoveAsset(assetID string) error {
	da.mutex.Lock()
	defer da.mutex.Unlock()

	if _, exists := da.assets[assetID]; !exists {
		return errors.New("asset not found")
	}

	delete(da.assets, assetID)
	da.logger.Println("Asset removed:", assetID)
	return nil
}

// GetAssetValue gets the value of an asset.
func (da *DynamicAdjustment) GetAssetValue(assetID string) (float64, error) {
	da.mutex.Lock()
	defer da.mutex.Unlock()

	asset, exists := da.assets[assetID]
	if !exists {
		return 0, errors.New("asset not found")
	}

	return asset.Value, nil
}

// AdjustAssetValue adjusts the value of an asset based on market conditions.
func (da *DynamicAdjustment) AdjustAssetValue(assetID string) error {
	da.mutex.Lock()
	defer da.mutex.Unlock()

	asset, exists := da.assets[assetID]
	if !exists {
		return errors.New("asset not found")
	}

	marketPrice, err := da.priceFeed.GetMarketPrice(assetID)
	if err != nil {
		return err
	}

	newValue, err := da.adjustmentAlgo.CalculateNewValue(asset.Value, marketPrice)
	if err != nil {
		return err
	}

	asset.Value = newValue
	asset.LastAdjustment = time.Now()
	da.logger.Println("Asset value adjusted:", assetID, "New value:", newValue)

	err = da.notificationSvc.SendNotification("Asset value adjusted: " + assetID)
	if err != nil {
		da.logger.Println("Failed to send notification for asset adjustment:", assetID, err)
	}

	return nil
}

// MonitorAssets continuously monitors and adjusts asset values.
func (da *DynamicAdjustment) MonitorAssets(interval time.Duration) {
	for {
		time.Sleep(interval)
		da.mutex.Lock()
		for assetID := range da.assets {
			da.mutex.Unlock()
			err := da.AdjustAssetValue(assetID)
			if err != nil {
				da.logger.Println("Failed to adjust asset value:", assetID, err)
			}
			da.mutex.Lock()
		}
		da.mutex.Unlock()
	}
}

// EncryptAssetData encrypts the asset data.
func (da *DynamicAdjustment) EncryptAssetData(assetID string, data []byte) ([]byte, error) {
	da.mutex.Lock()
	defer da.mutex.Unlock()

	asset, exists := da.assets[assetID]
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
func (da *DynamicAdjustment) DecryptAssetData(assetID string, encryptedData []byte) ([]byte, error) {
	da.mutex.Lock()
	defer da.mutex.Unlock()

	asset, exists := da.assets[assetID]
	if !exists {
		return nil, errors.New("asset not found")
	}

	decryptedData, err := crypto.DecryptAES(asset.ID, encryptedData)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}
