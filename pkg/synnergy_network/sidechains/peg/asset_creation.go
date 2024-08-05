// Package peg provides functionalities related to the pegging mechanism within the Synnergy Network blockchain.
// This asset_creation.go file implements the logic for creating assets within the network.

package peg

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"math/big"
	"sync"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/crypto"
)

// AssetCreator represents the asset creation mechanism.
type AssetCreator struct {
	assets map[string]*Asset
	mutex  sync.Mutex
	logger *log.Logger
}

// NewAssetCreator creates a new instance of AssetCreator.
func NewAssetCreator(logger *log.Logger) *AssetCreator {
	return &AssetCreator{
		assets: make(map[string]*Asset),
		logger: logger,
	}
}

// CreateAsset creates a new asset with the given name, initial supply, and owner.
func (ac *AssetCreator) CreateAsset(name string, initialSupply *big.Int, owner string) (*Asset, error) {
	ac.mutex.Lock()
	defer ac.mutex.Unlock()

	if _, exists := ac.assets[name]; exists {
		return nil, errors.New("asset already exists")
	}

	assetID, err := generateAssetID(name)
	if err != nil {
		return nil, err
	}

	asset := &Asset{
		ID:            assetID,
		Name:          name,
		TotalSupply:   initialSupply,
		Owner:         owner,
		InitialSupply: initialSupply,
	}

	ac.assets[name] = asset
	ac.logger.Println("Asset created:", asset)
	return asset, nil
}

// generateAssetID generates a unique ID for the asset using its name and a random salt.
func generateAssetID(name string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := sha256.New()
	hash.Write([]byte(name))
	hash.Write(salt)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// GetAsset returns the asset with the given name.
func (ac *AssetCreator) GetAsset(name string) (*Asset, error) {
	ac.mutex.Lock()
	defer ac.mutex.Unlock()

	asset, exists := ac.assets[name]
	if !exists {
		return nil, errors.New("asset not found")
	}

	return asset, nil
}

// ListAssets returns all created assets.
func (ac *AssetCreator) ListAssets() []*Asset {
	ac.mutex.Lock()
	defer ac.mutex.Unlock()

	var assets []*Asset
	for _, asset := range ac.assets {
		assets = append(assets, asset)
	}
	return assets
}

// TransferAsset transfers the specified amount of the asset from one owner to another.
func (ac *AssetCreator) TransferAsset(name string, from string, to string, amount *big.Int) error {
	ac.mutex.Lock()
	defer ac.mutex.Unlock()

	asset, exists := ac.assets[name]
	if !exists {
		return errors.New("asset not found")
	}

	if asset.Owner != from {
		return errors.New("only the owner can transfer the asset")
	}

	if asset.TotalSupply.Cmp(amount) < 0 {
		return errors.New("insufficient asset supply")
	}

	asset.TotalSupply.Sub(asset.TotalSupply, amount)
	// Transfer logic to be implemented based on the blockchain's account mechanism.
	// For example, updating balances in the account state.

	ac.logger.Println("Asset transferred:", name, "from", from, "to", to, "amount", amount)
	return nil
}

// Asset represents an asset within the Synnergy Network.
type Asset struct {
	ID            string
	Name          string
	TotalSupply   *big.Int
	Owner         string
	InitialSupply *big.Int
}

// CryptoUtils provides cryptographic utilities for the Synnergy Network.
type CryptoUtils struct{}

// GenerateKeyPair generates a new public-private key pair.
func (cu *CryptoUtils) GenerateKeyPair() (string, string, error) {
	privateKey, err := crypto.GeneratePrivateKey()
	if err != nil {
		return "", "", err
	}

	publicKey := crypto.GeneratePublicKey(privateKey)
	return privateKey, publicKey, nil
}

// EncryptData encrypts data using the specified key.
func (cu *CryptoUtils) EncryptData(key, data string) (string, error) {
	encryptedData, err := crypto.EncryptAES(key, data)
	if err != nil {
		return "", err
	}
	return encryptedData, nil
}

// DecryptData decrypts data using the specified key.
func (cu *CryptoUtils) DecryptData(key, encryptedData string) (string, error) {
	decryptedData, err := crypto.DecryptAES(key, encryptedData)
	if err != nil {
		return "", err
	}
	return decryptedData, nil
}
