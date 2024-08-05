package ledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/synnergy_network/core/tokens/token_standards/syn131/assets"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/events"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/storage"
)

// OwnershipLedger represents the ownership ledger for SYN131 token standard
type OwnershipLedger struct {
	Storage         storage.Storage
	EventDispatcher events.EventDispatcher
	mutex           sync.Mutex
}

// NewOwnershipLedger initializes a new OwnershipLedger instance
func NewOwnershipLedger(storage storage.Storage, eventDispatcher events.EventDispatcher) *OwnershipLedger {
	return &OwnershipLedger{
		Storage:         storage,
		EventDispatcher: eventDispatcher,
	}
}

// AddOwnershipRecord adds a new ownership record to the ledger
func (ledger *OwnershipLedger) AddOwnershipRecord(assetID, ownerID string) error {
	ledger.mutex.Lock()
	defer ledger.mutex.Unlock()

	ownershipKey := fmt.Sprintf("ownership_%s", assetID)
	record := assets.OwnershipRecord{
		AssetID: assetID,
		OwnerID: ownerID,
	}

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal ownership record: %w", err)
	}

	if err := ledger.Storage.Save(ownershipKey, data); err != nil {
		return fmt.Errorf("failed to save ownership record: %w", err)
	}

	event := events.Event{
		Type:    events.OwnershipAdded,
		Payload: map[string]interface{}{"assetID": assetID, "ownerID": ownerID},
	}
	if err := ledger.EventDispatcher.Dispatch(event); err != nil {
		return fmt.Errorf("failed to dispatch ownership added event: %w", err)
	}

	return nil
}

// GetOwnershipRecord retrieves an ownership record from the ledger by asset ID
func (ledger *OwnershipLedger) GetOwnershipRecord(assetID string) (assets.OwnershipRecord, error) {
	data, err := ledger.Storage.Load(fmt.Sprintf("ownership_%s", assetID))
	if err != nil {
		return assets.OwnershipRecord{}, fmt.Errorf("failed to load ownership record: %w", err)
	}

	var record assets.OwnershipRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return assets.OwnershipRecord{}, fmt.Errorf("failed to unmarshal ownership record: %w", err)
	}

	return record, nil
}

// UpdateOwnershipRecord updates an existing ownership record in the ledger
func (ledger *OwnershipLedger) UpdateOwnershipRecord(assetID, newOwnerID string) error {
	ledger.mutex.Lock()
	defer ledger.mutex.Unlock()

	ownershipKey := fmt.Sprintf("ownership_%s", assetID)
	record := assets.OwnershipRecord{
		AssetID: assetID,
		OwnerID: newOwnerID,
	}

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal ownership record: %w", err)
	}

	if err := ledger.Storage.Save(ownershipKey, data); err != nil {
		return fmt.Errorf("failed to save ownership record: %w", err)
	}

	event := events.Event{
		Type:    events.OwnershipUpdated,
		Payload: map[string]interface{}{"assetID": assetID, "ownerID": newOwnerID},
	}
	if err := ledger.EventDispatcher.Dispatch(event); err != nil {
		return fmt.Errorf("failed to dispatch ownership updated event: %w", err)
	}

	return nil
}

// DeleteOwnershipRecord removes an ownership record from the ledger
func (ledger *OwnershipLedger) DeleteOwnershipRecord(assetID string) error {
	ledger.mutex.Lock()
	defer ledger.mutex.Unlock()

	ownershipKey := fmt.Sprintf("ownership_%s", assetID)
	if err := ledger.Storage.Delete(ownershipKey); err != nil {
		return fmt.Errorf("failed to delete ownership record: %w", err)
	}

	event := events.Event{
		Type:    events.OwnershipDeleted,
		Payload: map[string]interface{}{"assetID": assetID},
	}
	if err := ledger.EventDispatcher.Dispatch(event); err != nil {
		return fmt.Errorf("failed to dispatch ownership deleted event: %w", err)
	}

	return nil
}

// ListOwnershipRecords lists all ownership records stored in the ledger
func (ledger *OwnershipLedger) ListOwnershipRecords() ([]assets.OwnershipRecord, error) {
	keys, err := ledger.Storage.GetKeysByPrefix("ownership_")
	if err != nil {
		return nil, fmt.Errorf("failed to get ownership keys: %w", err)
	}

	var records []assets.OwnershipRecord
	for _, key := range keys {
		data, err := ledger.Storage.Load(key)
		if err != nil {
			return nil, fmt.Errorf("failed to load ownership record: %w", err)
		}

		var record assets.OwnershipRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return nil, fmt.Errorf("failed to unmarshal ownership record: %w", err)
		}

		records = append(records, record)
	}

	return records, nil
}

// VerifyOwnership verifies if a given owner owns the asset
func (ledger *OwnershipLedger) VerifyOwnership(assetID, ownerID string) (bool, error) {
	record, err := ledger.GetOwnershipRecord(assetID)
	if err != nil {
		return false, fmt.Errorf("failed to get ownership record: %w", err)
	}

	if record.OwnerID == ownerID {
		return true, nil
	}

	return false, nil
}

// EncryptAndStore encrypts and stores sensitive data
func (ledger *OwnershipLedger) EncryptAndStore(key string, data []byte, passphrase string) error {
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
func (ledger *OwnershipLedger) DecryptAndRetrieve(key string, passphrase string) ([]byte, error) {
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
