package ledger

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/synnergy_network/core/tokens/token_standards/syn131/events"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn131/storage"
)

// TransactionRecord represents a transaction in the ledger
type TransactionRecord struct {
	TransactionID string `json:"transaction_id"`
	From          string `json:"from"`
	To            string `json:"to"`
	AssetID       string `json:"asset_id"`
	Timestamp     int64  `json:"timestamp"`
	Amount        string `json:"amount"`
	Status        string `json:"status"`
}

// TransactionLedger represents the ledger for SYN131 token transactions
type TransactionLedger struct {
	Storage         storage.Storage
	EventDispatcher events.EventDispatcher
	mutex           sync.Mutex
}

// NewTransactionLedger initializes a new TransactionLedger instance
func NewTransactionLedger(storage storage.Storage, eventDispatcher events.EventDispatcher) *TransactionLedger {
	return &TransactionLedger{
		Storage:         storage,
		EventDispatcher: eventDispatcher,
	}
}

// AddTransaction adds a new transaction to the ledger
func (ledger *TransactionLedger) AddTransaction(record TransactionRecord) error {
	ledger.mutex.Lock()
	defer ledger.mutex.Unlock()

	transactionKey := fmt.Sprintf("transaction_%s", record.TransactionID)
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction record: %w", err)
	}

	if err := ledger.Storage.Save(transactionKey, data); err != nil {
		return fmt.Errorf("failed to save transaction record: %w", err)
	}

	event := events.Event{
		Type:    events.TransactionAdded,
		Payload: map[string]interface{}{"transactionID": record.TransactionID, "from": record.From, "to": record.To, "assetID": record.AssetID, "amount": record.Amount, "status": record.Status},
	}
	if err := ledger.EventDispatcher.Dispatch(event); err != nil {
		return fmt.Errorf("failed to dispatch transaction added event: %w", err)
	}

	return nil
}

// GetTransaction retrieves a transaction from the ledger by transaction ID
func (ledger *TransactionLedger) GetTransaction(transactionID string) (TransactionRecord, error) {
	data, err := ledger.Storage.Load(fmt.Sprintf("transaction_%s", transactionID))
	if err != nil {
		return TransactionRecord{}, fmt.Errorf("failed to load transaction record: %w", err)
	}

	var record TransactionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return TransactionRecord{}, fmt.Errorf("failed to unmarshal transaction record: %w", err)
	}

	return record, nil
}

// UpdateTransaction updates an existing transaction in the ledger
func (ledger *TransactionLedger) UpdateTransaction(record TransactionRecord) error {
	ledger.mutex.Lock()
	defer ledger.mutex.Unlock()

	transactionKey := fmt.Sprintf("transaction_%s", record.TransactionID)
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction record: %w", err)
	}

	if err := ledger.Storage.Save(transactionKey, data); err != nil {
		return fmt.Errorf("failed to save transaction record: %w", err)
	}

	event := events.Event{
		Type:    events.TransactionUpdated,
		Payload: map[string]interface{}{"transactionID": record.TransactionID, "from": record.From, "to": record.To, "assetID": record.AssetID, "amount": record.Amount, "status": record.Status},
	}
	if err := ledger.EventDispatcher.Dispatch(event); err != nil {
		return fmt.Errorf("failed to dispatch transaction updated event: %w", err)
	}

	return nil
}

// DeleteTransaction removes a transaction from the ledger
func (ledger *TransactionLedger) DeleteTransaction(transactionID string) error {
	ledger.mutex.Lock()
	defer ledger.mutex.Unlock()

	transactionKey := fmt.Sprintf("transaction_%s", transactionID)
	if err := ledger.Storage.Delete(transactionKey); err != nil {
		return fmt.Errorf("failed to delete transaction record: %w", err)
	}

	event := events.Event{
		Type:    events.TransactionDeleted,
		Payload: map[string]interface{}{"transactionID": transactionID},
	}
	if err := ledger.EventDispatcher.Dispatch(event); err != nil {
		return fmt.Errorf("failed to dispatch transaction deleted event: %w", err)
	}

	return nil
}

// ListTransactions lists all transactions stored in the ledger
func (ledger *TransactionLedger) ListTransactions() ([]TransactionRecord, error) {
	keys, err := ledger.Storage.GetKeysByPrefix("transaction_")
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction keys: %w", err)
	}

	var records []TransactionRecord
	for _, key := range keys {
		data, err := ledger.Storage.Load(key)
		if err != nil {
			return nil, fmt.Errorf("failed to load transaction record: %w", err)
		}

		var record TransactionRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return nil, fmt.Errorf("failed to unmarshal transaction record: %w", err)
		}

		records = append(records, record)
	}

	return records, nil
}

// VerifyTransaction verifies if a transaction is valid
func (ledger *TransactionLedger) VerifyTransaction(transactionID string) (bool, error) {
	record, err := ledger.GetTransaction(transactionID)
	if err != nil {
		return false, fmt.Errorf("failed to get transaction record: %w", err)
	}

	// Add further validation logic here as per business rules

	if record.Status == "valid" {
		return true, nil
	}

	return false, nil
}

// EncryptAndStore encrypts and stores sensitive transaction data
func (ledger *TransactionLedger) EncryptAndStore(key string, data []byte, passphrase string) error {
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

// DecryptAndRetrieve decrypts and retrieves sensitive transaction data
func (ledger *TransactionLedger) DecryptAndRetrieve(key string, passphrase string) ([]byte, error) {
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
