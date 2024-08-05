package management

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/synnergy_network/core/tokens/token_standards/syn131/assets"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/events"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/storage"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/transactions"
)

type AssetManagementPlatform struct {
	Storage         storage.Storage
	OwnershipLedger *ledger.OwnershipLedger
	EventDispatcher events.EventDispatcher
	mutex           sync.Mutex
}

func NewAssetManagementPlatform(storage storage.Storage, ownershipLedger *ledger.OwnershipLedger, eventDispatcher events.EventDispatcher) *AssetManagementPlatform {
	return &AssetManagementPlatform{
		Storage:         storage,
		OwnershipLedger: ownershipLedger,
		EventDispatcher: eventDispatcher,
	}
}

// RegisterAsset registers a new asset on the platform
func (amp *AssetManagementPlatform) RegisterAsset(asset assets.AssetMetadata, owner string) error {
	amp.mutex.Lock()
	defer amp.mutex.Unlock()

	assetKey := fmt.Sprintf("asset_%s", asset.ID)
	data, err := json.Marshal(asset)
	if err != nil {
		return fmt.Errorf("failed to marshal asset metadata: %w", err)
	}

	if err := amp.Storage.Save(assetKey, data); err != nil {
		return fmt.Errorf("failed to save asset metadata: %w", err)
	}

	ownershipRecord := ledger.OwnershipRecord{
		AssetID: asset.ID,
		Owner:   owner,
	}

	if err := amp.OwnershipLedger.AddOwnership(ownershipRecord); err != nil {
		return fmt.Errorf("failed to add ownership record: %w", err)
	}

	event := events.Event{
		Type:    events.AssetRegistered,
		Payload: map[string]interface{}{"assetID": asset.ID, "owner": owner},
	}
	if err := amp.EventDispatcher.Dispatch(event); err != nil {
		return fmt.Errorf("failed to dispatch asset registered event: %w", err)
	}

	return nil
}

// GetAsset retrieves asset metadata by asset ID
func (amp *AssetManagementPlatform) GetAsset(assetID string) (assets.AssetMetadata, error) {
	data, err := amp.Storage.Load(fmt.Sprintf("asset_%s", assetID))
	if err != nil {
		return assets.AssetMetadata{}, fmt.Errorf("failed to load asset metadata: %w", err)
	}

	var asset assets.AssetMetadata
	if err := json.Unmarshal(data, &asset); err != nil {
		return assets.AssetMetadata{}, fmt.Errorf("failed to unmarshal asset metadata: %w", err)
	}

	return asset, nil
}

// UpdateAsset updates existing asset metadata
func (amp *AssetManagementPlatform) UpdateAsset(asset assets.AssetMetadata) error {
	amp.mutex.Lock()
	defer amp.mutex.Unlock()

	assetKey := fmt.Sprintf("asset_%s", asset.ID)
	data, err := json.Marshal(asset)
	if err != nil {
		return fmt.Errorf("failed to marshal asset metadata: %w", err)
	}

	if err := amp.Storage.Save(assetKey, data); err != nil {
		return fmt.Errorf("failed to save asset metadata: %w", err)
	}

	event := events.Event{
		Type:    events.AssetUpdated,
		Payload: map[string]interface{}{"assetID": asset.ID},
	}
	if err := amp.EventDispatcher.Dispatch(event); err != nil {
		return fmt.Errorf("failed to dispatch asset updated event: %w", err)
	}

	return nil
}

// TransferAssetOwnership transfers ownership of an asset to a new owner
func (amp *AssetManagementPlatform) TransferAssetOwnership(assetID, newOwner string) error {
	amp.mutex.Lock()
	defer amp.mutex.Unlock()

	ownershipRecord, err := amp.OwnershipLedger.GetOwnership(assetID)
	if err != nil {
		return fmt.Errorf("failed to get ownership record: %w", err)
	}

	ownershipRecord.Owner = newOwner

	if err := amp.OwnershipLedger.UpdateOwnership(ownershipRecord); err != nil {
		return fmt.Errorf("failed to update ownership record: %w", err)
	}

	event := events.Event{
		Type:    events.OwnershipTransferred,
		Payload: map[string]interface{}{"assetID": assetID, "newOwner": newOwner},
	}
	if err := amp.EventDispatcher.Dispatch(event); err != nil {
		return fmt.Errorf("failed to dispatch ownership transferred event: %w", err)
	}

	return nil
}

// EncryptAndStoreAssetMetadata encrypts and stores sensitive asset metadata
func (amp *AssetManagementPlatform) EncryptAndStoreAssetMetadata(assetID string, metadata []byte, passphrase string) error {
	salt, err := security.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	encryptedData, err := security.Encrypt(metadata, passphrase, salt)
	if err != nil {
		return fmt.Errorf("failed to encrypt metadata: %w", err)
	}

	storeData := append(salt, encryptedData...)
	if err := amp.Storage.Save(fmt.Sprintf("encrypted_asset_%s", assetID), storeData); err != nil {
		return fmt.Errorf("failed to save encrypted metadata: %w", err)
	}

	return nil
}

// DecryptAndRetrieveAssetMetadata decrypts and retrieves sensitive asset metadata
func (amp *AssetManagementPlatform) DecryptAndRetrieveAssetMetadata(assetID string, passphrase string) ([]byte, error) {
	storeData, err := amp.Storage.Load(fmt.Sprintf("encrypted_asset_%s", assetID))
	if err != nil {
		return nil, fmt.Errorf("failed to load encrypted metadata: %w", err)
	}

	salt := storeData[:security.SaltSize]
	encryptedData := storeData[security.SaltSize:]

	data, err := security.Decrypt(encryptedData, passphrase, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt metadata: %w", err)
	}

	return data, nil
}

// ListAssets lists all registered assets
func (amp *AssetManagementPlatform) ListAssets() ([]assets.AssetMetadata, error) {
	keys, err := amp.Storage.GetKeysByPrefix("asset_")
	if err != nil {
		return nil, fmt.Errorf("failed to get asset keys: %w", err)
	}

	var assetsList []assets.AssetMetadata
	for _, key := range keys {
		data, err := amp.Storage.Load(key)
		if err != nil {
			return nil, fmt.Errorf("failed to load asset metadata: %w", err)
		}

		var asset assets.AssetMetadata
		if err := json.Unmarshal(data, &asset); err != nil {
			return nil, fmt.Errorf("failed to unmarshal asset metadata: %w", err)
		}

		assetsList = append(assetsList, asset)
	}

	return assetsList, nil
}

// DeleteAsset deletes an asset from the platform
func (amp *AssetManagementPlatform) DeleteAsset(assetID string) error {
	amp.mutex.Lock()
	defer amp.mutex.Unlock()

	if err := amp.Storage.Delete(fmt.Sprintf("asset_%s", assetID)); err != nil {
		return fmt.Errorf("failed to delete asset metadata: %w", err)
	}

	if err := amp.OwnershipLedger.DeleteOwnership(assetID); err != nil {
		return fmt.Errorf("failed to delete ownership record: %w", err)
	}

	event := events.Event{
		Type:    events.AssetDeleted,
		Payload: map[string]interface{}{"assetID": assetID},
	}
	if err := amp.EventDispatcher.Dispatch(event); err != nil {
		return fmt.Errorf("failed to dispatch asset deleted event: %w", err)
	}

	return nil
}

// ValidateOwnership validates the ownership of an asset
func (amp *AssetManagementPlatform) ValidateOwnership(assetID, owner string) (bool, error) {
	ownershipRecord, err := amp.OwnershipLedger.GetOwnership(assetID)
	if err != nil {
		return false, fmt.Errorf("failed to get ownership record: %w", err)
	}

	return ownershipRecord.Owner == owner, nil
}

// GenerateReport generates a comprehensive report of all assets and their ownership
func (amp *AssetManagementPlatform) GenerateReport() (map[string]interface{}, error) {
	assets, err := amp.ListAssets()
	if err != nil {
		return nil, fmt.Errorf("failed to list assets: %w", err)
	}

	report := make(map[string]interface{})
	for _, asset := range assets {
		ownership, err := amp.OwnershipLedger.GetOwnership(asset.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get ownership record for asset %s: %w", asset.ID, err)
		}

		report[asset.ID] = map[string]interface{}{
			"asset":    asset,
			"owner":    ownership.Owner,
			"metadata": asset.Metadata,
		}
	}

	return report, nil
}
