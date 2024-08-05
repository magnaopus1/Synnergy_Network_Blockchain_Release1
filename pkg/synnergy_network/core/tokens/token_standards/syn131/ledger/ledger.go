package ledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/assets"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/events"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/storage"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/transactions"
	"sync"
)

// Ledger represents the main ledger for SYN131 token standard
type Ledger struct {
	Storage         storage.Storage
	EventDispatcher events.EventDispatcher
	mutex           sync.Mutex
}

// NewLedger initializes a new Ledger instance
func NewLedger(storage storage.Storage, eventDispatcher events.EventDispatcher) *Ledger {
	return &Ledger{
		Storage:         storage,
		EventDispatcher: eventDispatcher,
	}
}

// AddAsset adds a new asset to the ledger
func (ledger *Ledger) AddAsset(asset assets.Asset) error {
	ledger.mutex.Lock()
	defer ledger.mutex.Unlock()

	data, err := json.Marshal(asset)
	if err != nil {
		return fmt.Errorf("failed to marshal asset: %w", err)
	}

	assetKey := fmt.Sprintf("asset_%s", asset.ID)
	if err := ledger.Storage.Save(assetKey, data); err != nil {
		return fmt.Errorf("failed to save asset: %w", err)
	}

	event := events.Event{
		Type:    events.AssetAdded,
		Payload: map[string]interface{}{"assetID": asset.ID},
	}
	if err := ledger.EventDispatcher.Dispatch(event); err != nil {
		return fmt.Errorf("failed to dispatch asset added event: %w", err)
	}

	return nil
}

// GetAsset retrieves an asset from the ledger by its ID
func (ledger *Ledger) GetAsset(assetID string) (assets.Asset, error) {
	data, err := ledger.Storage.Load(fmt.Sprintf("asset_%s", assetID))
	if err != nil {
		return assets.Asset{}, fmt.Errorf("failed to load asset: %w", err)
	}

	var asset assets.Asset
	if err := json.Unmarshal(data, &asset); err != nil {
		return assets.Asset{}, fmt.Errorf("failed to unmarshal asset: %w", err)
	}

	return asset, nil
}

// UpdateAsset updates an existing asset in the ledger
func (ledger *Ledger) UpdateAsset(asset assets.Asset) error {
	ledger.mutex.Lock()
	defer ledger.mutex.Unlock()

	data, err := json.Marshal(asset)
	if err != nil {
		return fmt.Errorf("failed to marshal asset: %w", err)
	}

	assetKey := fmt.Sprintf("asset_%s", asset.ID)
	if err := ledger.Storage.Save(assetKey, data); err != nil {
		return fmt.Errorf("failed to save asset: %w", err)
	}

	event := events.Event{
		Type:    events.AssetUpdated,
		Payload: map[string]interface{}{"assetID": asset.ID},
	}
	if err := ledger.EventDispatcher.Dispatch(event); err != nil {
		return fmt.Errorf("failed to dispatch asset updated event: %w", err)
	}

	return nil
}

// DeleteAsset removes an asset from the ledger
func (ledger *Ledger) DeleteAsset(assetID string) error {
	ledger.mutex.Lock()
	defer ledger.mutex.Unlock()

	assetKey := fmt.Sprintf("asset_%s", assetID)
	if err := ledger.Storage.Delete(assetKey); err != nil {
		return fmt.Errorf("failed to delete asset: %w", err)
	}

	event := events.Event{
		Type:    events.AssetDeleted,
		Payload: map[string]interface{}{"assetID": assetID},
	}
	if err := ledger.EventDispatcher.Dispatch(event); err != nil {
		return fmt.Errorf("failed to dispatch asset deleted event: %w", err)
	}

	return nil
}

// AddTransaction adds a new transaction to the ledger
func (ledger *Ledger) AddTransaction(tx transactions.Transaction) error {
	ledger.mutex.Lock()
	defer ledger.mutex.Unlock()

	data, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction: %w", err)
	}

	txKey := fmt.Sprintf("transaction_%s", tx.ID)
	if err := ledger.Storage.Save(txKey, data); err != nil {
		return fmt.Errorf("failed to save transaction: %w", err)
	}

	event := events.Event{
		Type:    events.TransactionAdded,
		Payload: map[string]interface{}{"transactionID": tx.ID},
	}
	if err := ledger.EventDispatcher.Dispatch(event); err != nil {
		return fmt.Errorf("failed to dispatch transaction added event: %w", err)
	}

	return nil
}

// GetTransaction retrieves a transaction from the ledger by its ID
func (ledger *Ledger) GetTransaction(txID string) (transactions.Transaction, error) {
	data, err := ledger.Storage.Load(fmt.Sprintf("transaction_%s", txID))
	if err != nil {
		return transactions.Transaction{}, fmt.Errorf("failed to load transaction: %w", err)
	}

	var tx transactions.Transaction
	if err := json.Unmarshal(data, &tx); err != nil {
		return transactions.Transaction{}, fmt.Errorf("failed to unmarshal transaction: %w", err)
	}

	return tx, nil
}

// ListAssets lists all assets stored in the ledger
func (ledger *Ledger) ListAssets() ([]assets.Asset, error) {
	keys, err := ledger.Storage.GetKeysByPrefix("asset_")
	if err != nil {
		return nil, fmt.Errorf("failed to get asset keys: %w", err)
	}

	var assetsList []assets.Asset
	for _, key := range keys {
		data, err := ledger.Storage.Load(key)
		if err != nil {
			return nil, fmt.Errorf("failed to load asset: %w", err)
		}

		var asset assets.Asset
		if err := json.Unmarshal(data, &asset); err != nil {
			return nil, fmt.Errorf("failed to unmarshal asset: %w", err)
		}

		assetsList = append(assetsList, asset)
	}

	return assetsList, nil
}

// ListTransactions lists all transactions stored in the ledger
func (ledger *Ledger) ListTransactions() ([]transactions.Transaction, error) {
	keys, err := ledger.Storage.GetKeysByPrefix("transaction_")
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction keys: %w", err)
	}

	var txList []transactions.Transaction
	for _, key := range keys {
		data, err := ledger.Storage.Load(key)
		if err != nil {
			return nil, fmt.Errorf("failed to load transaction: %w", err)
		}

		var tx transactions.Transaction
		if err := json.Unmarshal(data, &tx); err != nil {
			return nil, fmt.Errorf("failed to unmarshal transaction: %w", err)
		}

		txList = append(txList, tx)
	}

	return txList, nil
}

// EncryptAndStore encrypts and stores sensitive data
func (ledger *Ledger) EncryptAndStore(key string, data []byte, passphrase string) error {
	salt, err := security.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	encryptedData, err := security.Encrypt(data, passphrase, salt)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	storeData := append(salt, encryptedData...)
	if err := ledger.Storage.Save(key, storeData); err != nil {
		return fmt.Errorf("failed to save encrypted data: %w", err)
	}

	return nil
}

// DecryptAndRetrieve decrypts and retrieves sensitive data
func (ledger *Ledger) DecryptAndRetrieve(key string, passphrase string) ([]byte, error) {
	storeData, err := ledger.Storage.Load(key)
	if err != nil {
		return nil, fmt.Errorf("failed to load encrypted data: %w", err)
	}

	salt := storeData[:security.SaltSize]
	encryptedData := storeData[security.SaltSize:]

	data, err := security.Decrypt(encryptedData, passphrase, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return data, nil
}
