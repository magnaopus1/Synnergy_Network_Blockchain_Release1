package peg

import (
	"errors"
	"log"
	"math"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/crypto"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/util"
)

// OptimizationService represents a service for optimizing the peg system.
type OptimizationService struct {
	assets           map[string]*Asset
	mutex            sync.Mutex
	logger           *log.Logger
	optimizationFreq time.Duration
}

// Asset represents an asset in the peg system.
type Asset struct {
	ID             string
	Value          float64
	LastOptimized  time.Time
	OptimizationScore float64
}

// NewOptimizationService creates a new instance of OptimizationService.
func NewOptimizationService(logger *log.Logger, freq time.Duration) *OptimizationService {
	return &OptimizationService{
		assets:           make(map[string]*Asset),
		logger:           logger,
		optimizationFreq: freq,
	}
}

// AddAsset adds a new asset to the optimization service.
func (os *OptimizationService) AddAsset(assetID string, initialValue float64) error {
	os.mutex.Lock()
	defer os.mutex.Unlock()

	if _, exists := os.assets[assetID]; exists {
		return errors.New("asset already exists")
	}

	asset := &Asset{
		ID:                assetID,
		Value:             initialValue,
		LastOptimized:     time.Now(),
		OptimizationScore: 0,
	}

	os.assets[assetID] = asset
	os.logger.Println("New asset added for optimization:", assetID)
	return nil
}

// RemoveAsset removes an asset from the optimization service.
func (os *OptimizationService) RemoveAsset(assetID string) error {
	os.mutex.Lock()
	defer os.mutex.Unlock()

	if _, exists := os.assets[assetID]; !exists {
		return errors.New("asset not found")
	}

	delete(os.assets, assetID)
	os.logger.Println("Asset removed from optimization:", assetID)
	return nil
}

// OptimizeAssets optimizes the performance and value of all assets.
func (os *OptimizationService) OptimizeAssets() {
	for {
		time.Sleep(os.optimizationFreq)
		os.mutex.Lock()
		for assetID, asset := range os.assets {
			os.mutex.Unlock()
			err := os.optimizeAsset(asset)
			if err != nil {
				os.logger.Println("Failed to optimize asset:", assetID, err)
			}
			os.mutex.Lock()
		}
		os.mutex.Unlock()
	}
}

// optimizeAsset optimizes the performance and value of a single asset.
func (os *OptimizationService) optimizeAsset(asset *Asset) error {
	// Simulate optimization operation
	asset.LastOptimized = time.Now()
	asset.OptimizationScore = calculateOptimizationScore(asset.Value)
	os.logger.Println("Optimized asset:", asset.ID, "OptimizationScore:", asset.OptimizationScore)

	return nil
}

// calculateOptimizationScore calculates an optimization score based on the asset's value.
func calculateOptimizationScore(value float64) float64 {
	return math.Sqrt(value) * 1.25 // Example logic, should be replaced with real optimization logic
}

// EncryptAssetData encrypts the asset data.
func (os *OptimizationService) EncryptAssetData(assetID string, data []byte) ([]byte, error) {
	os.mutex.Lock()
	defer os.mutex.Unlock()

	asset, exists := os.assets[assetID]
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
func (os *OptimizationService) DecryptAssetData(assetID string, encryptedData []byte) ([]byte, error) {
	os.mutex.Lock()
	defer os.mutex.Unlock()

	asset, exists := os.assets[assetID]
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
func (os *OptimizationService) BackupAssets() (map[string]*Asset, error) {
	os.mutex.Lock()
	defer os.mutex.Unlock()

	backup := make(map[string]*Asset)
	for id, asset := range os.assets {
		backup[id] = &Asset{
			ID:                asset.ID,
			Value:             asset.Value,
			LastOptimized:     asset.LastOptimized,
			OptimizationScore: asset.OptimizationScore,
		}
	}

	os.logger.Println("Assets backup created")
	return backup, nil
}

// RestoreAssets restores assets from a backup.
func (os *OptimizationService) RestoreAssets(backup map[string]*Asset) error {
	os.mutex.Lock()
	defer os.mutex.Unlock()

	for id, asset := range backup {
		os.assets[id] = &Asset{
			ID:                asset.ID,
			Value:             asset.Value,
			LastOptimized:     asset.LastOptimized,
			OptimizationScore: asset.OptimizationScore,
		}
	}

	os.logger.Println("Assets restored from backup")
	return nil
}

// AdjustOptimizationFrequency adjusts the frequency of optimization.
func (os *OptimizationService) AdjustOptimizationFrequency(freq time.Duration) {
	os.mutex.Lock()
	defer os.mutex.Unlock()

	os.optimizationFreq = freq
	os.logger.Println("Optimization frequency adjusted to:", freq)
}

// LogOptimizationDetails logs detailed information about the optimization process.
func (os *OptimizationService) LogOptimizationDetails() {
	os.mutex.Lock()
	defer os.mutex.Unlock()

	for id, asset := range os.assets {
		os.logger.Printf("AssetID: %s, Value: %f, LastOptimized: %s, OptimizationScore: %f\n", id, asset.Value, asset.LastOptimized, asset.OptimizationScore)
	}
}
