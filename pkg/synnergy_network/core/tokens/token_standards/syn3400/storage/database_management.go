package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/events"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/ledger"
)

// DatabaseManager handles the storage and retrieval of data related to the SYN3400 token standard.
type DatabaseManager struct {
	mu             sync.Mutex
	filePath       string
	forexPairs     map[string]assets.ForexMetadata
	ownerships     map[string]string
	transactions   []ledger.TransactionRecord
	positionProfit map[string]float64
}

// NewDatabaseManager initializes a new DatabaseManager.
func NewDatabaseManager(filePath string) *DatabaseManager {
	return &DatabaseManager{
		filePath:       filePath,
		forexPairs:     make(map[string]assets.ForexMetadata),
		ownerships:     make(map[string]string),
		transactions:   []ledger.TransactionRecord{},
		positionProfit: make(map[string]float64),
	}
}

// LoadDatabase loads the database from a file.
func (db *DatabaseManager) LoadDatabase() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	file, err := os.Open(db.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	return decoder.Decode(db)
}

// SaveDatabase saves the database to a file.
func (db *DatabaseManager) SaveDatabase() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	file, err := os.Create(db.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(db)
}

// AddForexPair adds a new Forex pair to the database.
func (db *DatabaseManager) AddForexPair(metadata assets.ForexMetadata) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.forexPairs[metadata.PairID]; exists {
		return errors.New("Forex pair already exists")
	}

	db.forexPairs[metadata.PairID] = metadata

	event := events.NewEventLogging()
	event.LogEvent("ForexPairAdded", fmt.Sprintf("Forex pair added: %+v", metadata))

	return db.SaveDatabase()
}

// UpdateForexPair updates an existing Forex pair in the database.
func (db *DatabaseManager) UpdateForexPair(metadata assets.ForexMetadata) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.forexPairs[metadata.PairID]; !exists {
		return errors.New("Forex pair does not exist")
	}

	db.forexPairs[metadata.PairID] = metadata

	event := events.NewEventLogging()
	event.LogEvent("ForexPairUpdated", fmt.Sprintf("Forex pair updated: %+v", metadata))

	return db.SaveDatabase()
}

// GetForexPair retrieves a Forex pair from the database.
func (db *DatabaseManager) GetForexPair(pairID string) (assets.ForexMetadata, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	metadata, exists := db.forexPairs[pairID]
	if !exists {
		return assets.ForexMetadata{}, errors.New("Forex pair not found")
	}

	return metadata, nil
}

// ListAllForexPairs lists all Forex pairs in the database.
func (db *DatabaseManager) ListAllForexPairs() []assets.ForexMetadata {
	db.mu.Lock()
	defer db.mu.Unlock()

	pairs := make([]assets.ForexMetadata, 0, len(db.forexPairs))
	for _, metadata := range db.forexPairs {
		pairs = append(pairs, metadata)
	}

	return pairs
}

// RecordTransaction records a new transaction in the database.
func (db *DatabaseManager) RecordTransaction(record ledger.TransactionRecord) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.transactions = append(db.transactions, record)

	event := events.NewEventLogging()
	event.LogEvent("TransactionRecorded", fmt.Sprintf("Transaction recorded: %+v", record))

	return db.SaveDatabase()
}

// GetTransactionHistory retrieves the transaction history from the database.
func (db *DatabaseManager) GetTransactionHistory() []ledger.TransactionRecord {
	db.mu.Lock()
	defer db.mu.Unlock()

	return db.transactions
}

// UpdateOwnership updates the ownership information of a Forex position.
func (db *DatabaseManager) UpdateOwnership(positionID, newOwner string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.ownerships[positionID] = newOwner

	event := events.NewEventLogging()
	event.LogEvent("OwnershipUpdated", fmt.Sprintf("Ownership updated: PositionID=%s, NewOwner=%s", positionID, newOwner))

	return db.SaveDatabase()
}

// GetOwnership retrieves the ownership information of a Forex position.
func (db *DatabaseManager) GetOwnership(positionID string) (string, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	owner, exists := db.ownerships[positionID]
	if !exists {
		return "", errors.New("Ownership not found")
	}

	return owner, nil
}

// UpdatePositionProfitLoss updates the profit/loss of a speculative position.
func (db *DatabaseManager) UpdatePositionProfitLoss(positionID string, profitLoss float64) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.positionProfit[positionID] = profitLoss

	event := events.NewEventLogging()
	event.LogEvent("PositionProfitLossUpdated", fmt.Sprintf("Position profit/loss updated: PositionID=%s, ProfitLoss=%f", positionID, profitLoss))

	return db.SaveDatabase()
}

// GetPositionProfitLoss retrieves the profit/loss of a speculative position.
func (db *DatabaseManager) GetPositionProfitLoss(positionID string) (float64, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	profitLoss, exists := db.positionProfit[positionID]
	if !exists {
		return 0, errors.New("Profit/loss not found")
	}

	return profitLoss, nil
}

// BackupDatabase creates a backup of the current database state.
func (db *DatabaseManager) BackupDatabase(backupPath string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	file, err := os.Create(backupPath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(db)
}

// RestoreDatabase restores the database from a backup file.
func (db *DatabaseManager) RestoreDatabase(backupPath string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	file, err := os.Open(backupPath)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	return decoder.Decode(db)
}
