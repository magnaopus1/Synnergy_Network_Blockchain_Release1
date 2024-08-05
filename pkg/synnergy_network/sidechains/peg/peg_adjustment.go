package peg

import (
	"errors"
	"log"
	"math"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/crypto"
)

// PegAdjustmentService handles the dynamic adjustment of pegged assets.
type PegAdjustmentService struct {
	assets            map[string]*PeggedAsset
	mutex             sync.Mutex
	logger            *log.Logger
	adjustmentFreq    time.Duration
	adjustmentFactor  float64
}

// PeggedAsset represents an asset that is pegged to another value or asset.
type PeggedAsset struct {
	ID                string
	Value             float64
	LastAdjusted      time.Time
	AdjustmentScore   float64
	TargetValue       float64
}

// NewPegAdjustmentService creates a new instance of PegAdjustmentService.
func NewPegAdjustmentService(logger *log.Logger, freq time.Duration, factor float64) *PegAdjustmentService {
	return &PegAdjustmentService{
		assets:            make(map[string]*PeggedAsset),
		logger:            logger,
		adjustmentFreq:    freq,
		adjustmentFactor:  factor,
	}
}

// AddPeggedAsset adds a new pegged asset to the adjustment service.
func (pas *PegAdjustmentService) AddPeggedAsset(assetID string, initialValue, targetValue float64) error {
	pas.mutex.Lock()
	defer pas.mutex.Unlock()

	if _, exists := pas.assets[assetID]; exists {
		return errors.New("pegged asset already exists")
	}

	asset := &PeggedAsset{
		ID:               assetID,
		Value:            initialValue,
		LastAdjusted:     time.Now(),
		AdjustmentScore:  0,
		TargetValue:      targetValue,
	}

	pas.assets[assetID] = asset
	pas.logger.Println("New pegged asset added for adjustment:", assetID)
	return nil
}

// RemovePeggedAsset removes a pegged asset from the adjustment service.
func (pas *PegAdjustmentService) RemovePeggedAsset(assetID string) error {
	pas.mutex.Lock()
	defer pas.mutex.Unlock()

	if _, exists := pas.assets[assetID]; !exists {
		return errors.New("pegged asset not found")
	}

	delete(pas.assets, assetID)
	pas.logger.Println("Pegged asset removed from adjustment:", assetID)
	return nil
}

// AdjustPeggedAssets adjusts the value of all pegged assets at the specified frequency.
func (pas *PegAdjustmentService) AdjustPeggedAssets() {
	for {
		time.Sleep(pas.adjustmentFreq)
		pas.mutex.Lock()
		for assetID, asset := range pas.assets {
			pas.mutex.Unlock()
			err := pas.adjustPeggedAsset(asset)
			if err != nil {
				pas.logger.Println("Failed to adjust pegged asset:", assetID, err)
			}
			pas.mutex.Lock()
		}
		pas.mutex.Unlock()
	}
}

// adjustPeggedAsset adjusts the value of a single pegged asset.
func (pas *PegAdjustmentService) adjustPeggedAsset(asset *PeggedAsset) error {
	// Calculate adjustment score
	asset.LastAdjusted = time.Now()
	asset.AdjustmentScore = calculateAdjustmentScore(asset.Value, asset.TargetValue, pas.adjustmentFactor)
	// Adjust asset value
	asset.Value = asset.TargetValue * (1 + asset.AdjustmentScore)
	pas.logger.Println("Adjusted pegged asset:", asset.ID, "New Value:", asset.Value, "AdjustmentScore:", asset.AdjustmentScore)

	return nil
}

// calculateAdjustmentScore calculates an adjustment score based on the current and target values.
func calculateAdjustmentScore(currentValue, targetValue, factor float64) float64 {
	return (targetValue - currentValue) / targetValue * factor
}

// EncryptPeggedAssetData encrypts the pegged asset data.
func (pas *PegAdjustmentService) EncryptPeggedAssetData(assetID string, data []byte) ([]byte, error) {
	pas.mutex.Lock()
	defer pas.mutex.Unlock()

	asset, exists := pas.assets[assetID]
	if !exists {
		return nil, errors.New("pegged asset not found")
	}

	encryptedData, err := crypto.EncryptAES(asset.ID, data)
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}

// DecryptPeggedAssetData decrypts the pegged asset data.
func (pas *PegAdjustmentService) DecryptPeggedAssetData(assetID string, encryptedData []byte) ([]byte, error) {
	pas.mutex.Lock()
	defer pas.mutex.Unlock()

	asset, exists := pas.assets[assetID]
	if !exists {
		return nil, errors.New("pegged asset not found")
	}

	decryptedData, err := crypto.DecryptAES(asset.ID, encryptedData)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

// BackupPeggedAssets creates a backup of all pegged assets.
func (pas *PegAdjustmentService) BackupPeggedAssets() (map[string]*PeggedAsset, error) {
	pas.mutex.Lock()
	defer pas.mutex.Unlock()

	backup := make(map[string]*PeggedAsset)
	for id, asset := range pas.assets {
		backup[id] = &PeggedAsset{
			ID:               asset.ID,
			Value:            asset.Value,
			LastAdjusted:     asset.LastAdjusted,
			AdjustmentScore:  asset.AdjustmentScore,
			TargetValue:      asset.TargetValue,
		}
	}

	pas.logger.Println("Pegged assets backup created")
	return backup, nil
}

// RestorePeggedAssets restores pegged assets from a backup.
func (pas *PegAdjustmentService) RestorePeggedAssets(backup map[string]*PeggedAsset) error {
	pas.mutex.Lock()
	defer pas.mutex.Unlock()

	for id, asset := range backup {
		pas.assets[id] = &PeggedAsset{
			ID:               asset.ID,
			Value:            asset.Value,
			LastAdjusted:     asset.LastAdjusted,
			AdjustmentScore:  asset.AdjustmentScore,
			TargetValue:      asset.TargetValue,
		}
	}

	pas.logger.Println("Pegged assets restored from backup")
	return nil
}

// AdjustAdjustmentFrequency adjusts the frequency of adjustment.
func (pas *PegAdjustmentService) AdjustAdjustmentFrequency(freq time.Duration) {
	pas.mutex.Lock()
	defer pas.mutex.Unlock()

	pas.adjustmentFreq = freq
	pas.logger.Println("Adjustment frequency adjusted to:", freq)
}

// LogAdjustmentDetails logs detailed information about the adjustment process.
func (pas *PegAdjustmentService) LogAdjustmentDetails() {
	pas.mutex.Lock()
	defer pas.mutex.Unlock()

	for id, asset := range pas.assets {
		pas.logger.Printf("PeggedAssetID: %s, Value: %f, LastAdjusted: %s, AdjustmentScore: %f, TargetValue: %f\n", id, asset.Value, asset.LastAdjusted, asset.AdjustmentScore, asset.TargetValue)
	}
}
