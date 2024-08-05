package peg

import (
	"errors"
	"log"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/crypto"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/util"
)

// InteractiveInterface represents an interface for user interaction with the peg system.
type InteractiveInterface struct {
	assets          map[string]*Asset
	mutex           sync.Mutex
	logger          *log.Logger
	adjustmentAlgo  AdjustmentAlgorithm
	priceFeed       PriceFeed
	notificationSvc NotificationService
	authService     AuthenticationService
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

// AuthenticationService represents a service for user authentication.
type AuthenticationService interface {
	AuthenticateUser(username, password string) (bool, error)
	GenerateToken(username string) (string, error)
	ValidateToken(token string) (bool, error)
}

// NewInteractiveInterface creates a new instance of InteractiveInterface.
func NewInteractiveInterface(logger *log.Logger, adjustmentAlgo AdjustmentAlgorithm, priceFeed PriceFeed, notificationSvc NotificationService, authService AuthenticationService) *InteractiveInterface {
	return &InteractiveInterface{
		assets:          make(map[string]*Asset),
		logger:          logger,
		adjustmentAlgo:  adjustmentAlgo,
		priceFeed:       priceFeed,
		notificationSvc: notificationSvc,
		authService:     authService,
	}
}

// AddAsset adds a new asset to the peg system.
func (ii *InteractiveInterface) AddAsset(assetID string, initialValue float64) error {
	ii.mutex.Lock()
	defer ii.mutex.Unlock()

	if _, exists := ii.assets[assetID]; exists {
		return errors.New("asset already exists")
	}

	asset := &Asset{
		ID:            assetID,
		Value:         initialValue,
		LastAdjustment: time.Now(),
	}

	ii.assets[assetID] = asset
	ii.logger.Println("New asset added:", assetID)
	return nil
}

// RemoveAsset removes an asset from the peg system.
func (ii *InteractiveInterface) RemoveAsset(assetID string) error {
	ii.mutex.Lock()
	defer ii.mutex.Unlock()

	if _, exists := ii.assets[assetID]; !exists {
		return errors.New("asset not found")
	}

	delete(ii.assets, assetID)
	ii.logger.Println("Asset removed:", assetID)
	return nil
}

// GetAssetValue gets the value of an asset.
func (ii *InteractiveInterface) GetAssetValue(assetID string) (float64, error) {
	ii.mutex.Lock()
	defer ii.mutex.Unlock()

	asset, exists := ii.assets[assetID]
	if !exists {
		return 0, errors.New("asset not found")
	}

	return asset.Value, nil
}

// AdjustAssetValue adjusts the value of an asset based on market conditions.
func (ii *InteractiveInterface) AdjustAssetValue(assetID string) error {
	ii.mutex.Lock()
	defer ii.mutex.Unlock()

	asset, exists := ii.assets[assetID]
	if !exists {
		return errors.New("asset not found")
	}

	marketPrice, err := ii.priceFeed.GetMarketPrice(assetID)
	if err != nil {
		return err
	}

	newValue, err := ii.adjustmentAlgo.CalculateNewValue(asset.Value, marketPrice)
	if err != nil {
		return err
	}

	asset.Value = newValue
	asset.LastAdjustment = time.Now()
	ii.logger.Println("Asset value adjusted:", assetID, "New value:", newValue)

	err = ii.notificationSvc.SendNotification("Asset value adjusted: " + assetID)
	if err != nil {
		ii.logger.Println("Failed to send notification for asset adjustment:", assetID, err)
	}

	return nil
}

// MonitorAssets continuously monitors and adjusts asset values.
func (ii *InteractiveInterface) MonitorAssets(interval time.Duration) {
	for {
		time.Sleep(interval)
		ii.mutex.Lock()
		for assetID := range ii.assets {
			ii.mutex.Unlock()
			err := ii.AdjustAssetValue(assetID)
			if err != nil {
				ii.logger.Println("Failed to adjust asset value:", assetID, err)
			}
			ii.mutex.Lock()
		}
		ii.mutex.Unlock()
	}
}

// EncryptAssetData encrypts the asset data.
func (ii *InteractiveInterface) EncryptAssetData(assetID string, data []byte) ([]byte, error) {
	ii.mutex.Lock()
	defer ii.mutex.Unlock()

	asset, exists := ii.assets[assetID]
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
func (ii *InteractiveInterface) DecryptAssetData(assetID string, encryptedData []byte) ([]byte, error) {
	ii.mutex.Lock()
	defer ii.mutex.Unlock()

	asset, exists := ii.assets[assetID]
	if !exists {
		return nil, errors.New("asset not found")
	}

	decryptedData, err := crypto.DecryptAES(asset.ID, encryptedData)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

// AuthenticateUser authenticates a user and generates a token.
func (ii *InteractiveInterface) AuthenticateUser(username, password string) (string, error) {
	authenticated, err := ii.authService.AuthenticateUser(username, password)
	if err != nil {
		return "", err
	}

	if !authenticated {
		return "", errors.New("authentication failed")
	}

	token, err := ii.authService.GenerateToken(username)
	if err != nil {
		return "", err
	}

	return token, nil
}

// ValidateToken validates a user token.
func (ii *InteractiveInterface) ValidateToken(token string) (bool, error) {
	return ii.authService.ValidateToken(token)
}

// AddAssetWithAuth adds a new asset to the peg system with user authentication.
func (ii *InteractiveInterface) AddAssetWithAuth(token, assetID string, initialValue float64) error {
	valid, err := ii.ValidateToken(token)
	if err != nil {
		return err
	}

	if !valid {
		return errors.New("invalid token")
	}

	return ii.AddAsset(assetID, initialValue)
}

// RemoveAssetWithAuth removes an asset from the peg system with user authentication.
func (ii *InteractiveInterface) RemoveAssetWithAuth(token, assetID string) error {
	valid, err := ii.ValidateToken(token)
	if err != nil {
		return err
	}

	if !valid {
		return errors.New("invalid token")
	}

	return ii.RemoveAsset(assetID)
}

// GetAssetValueWithAuth gets the value of an asset with user authentication.
func (ii *InteractiveInterface) GetAssetValueWithAuth(token, assetID string) (float64, error) {
	valid, err := ii.ValidateToken(token)
	if err != nil {
		return 0, err
	}

	if !valid {
		return 0, errors.New("invalid token")
	}

	return ii.GetAssetValue(assetID)
}

// AdjustAssetValueWithAuth adjusts the value of an asset based on market conditions with user authentication.
func (ii *InteractiveInterface) AdjustAssetValueWithAuth(token, assetID string) error {
	valid, err := ii.ValidateToken(token)
	if err != nil {
		return err
	}

	if !valid {
		return errors.New("invalid token")
	}

	return ii.AdjustAssetValue(assetID)
}
