package peg

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/crypto"
)

// PegRecord represents a record of a pegged asset's state at a given time.
type PegRecord struct {
	AssetID       string    `json:"asset_id"`
	Timestamp     time.Time `json:"timestamp"`
	Value         float64   `json:"value"`
	AdjustmentScore float64 `json:"adjustment_score"`
}

// PegRecordsService handles the storage and retrieval of pegged asset records.
type PegRecordsService struct {
	records        map[string][]PegRecord
	mutex          sync.Mutex
	logger         *log.Logger
	storagePath    string
	encryptionKey  []byte
}

// NewPegRecordsService creates a new instance of PegRecordsService.
func NewPegRecordsService(logger *log.Logger, storagePath string, encryptionKey []byte) *PegRecordsService {
	return &PegRecordsService{
		records:        make(map[string][]PegRecord),
		logger:         logger,
		storagePath:    storagePath,
		encryptionKey:  encryptionKey,
	}
}

// AddPegRecord adds a new record for a pegged asset.
func (prs *PegRecordsService) AddPegRecord(assetID string, value, adjustmentScore float64) error {
	prs.mutex.Lock()
	defer prs.mutex.Unlock()

	record := PegRecord{
		AssetID:       assetID,
		Timestamp:     time.Now(),
		Value:         value,
		AdjustmentScore: adjustmentScore,
	}

	prs.records[assetID] = append(prs.records[assetID], record)
	prs.logger.Println("New peg record added for asset:", assetID)
	return nil
}

// GetPegRecords retrieves all records for a given pegged asset.
func (prs *PegRecordsService) GetPegRecords(assetID string) ([]PegRecord, error) {
	prs.mutex.Lock()
	defer prs.mutex.Unlock()

	records, exists := prs.records[assetID]
	if !exists {
		return nil, errors.New("no records found for pegged asset")
	}

	return records, nil
}

// SaveRecordsToFile saves all peg records to a file with encryption.
func (prs *PegRecordsService) SaveRecordsToFile() error {
	prs.mutex.Lock()
	defer prs.mutex.Unlock()

	data, err := json.Marshal(prs.records)
	if err != nil {
		return fmt.Errorf("failed to marshal records: %v", err)
	}

	encryptedData, err := crypto.EncryptAES(prs.encryptionKey, data)
	if err != nil {
		return fmt.Errorf("failed to encrypt records: %v", err)
	}

	err = os.WriteFile(prs.storagePath, encryptedData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write records to file: %v", err)
	}

	prs.logger.Println("Peg records saved to file")
	return nil
}

// LoadRecordsFromFile loads peg records from a file with decryption.
func (prs *PegRecordsService) LoadRecordsFromFile() error {
	prs.mutex.Lock()
	defer prs.mutex.Unlock()

	encryptedData, err := os.ReadFile(prs.storagePath)
	if err != nil {
		return fmt.Errorf("failed to read records from file: %v", err)
	}

	data, err := crypto.DecryptAES(prs.encryptionKey, encryptedData)
	if err != nil {
		return fmt.Errorf("failed to decrypt records: %v", err)
	}

	err = json.Unmarshal(data, &prs.records)
	if err != nil {
		return fmt.Errorf("failed to unmarshal records: %v", err)
	}

	prs.logger.Println("Peg records loaded from file")
	return nil
}

// BackupPegRecords creates a backup of all peg records.
func (prs *PegRecordsService) BackupPegRecords() (map[string][]PegRecord, error) {
	prs.mutex.Lock()
	defer prs.mutex.Unlock()

	backup := make(map[string][]PegRecord)
	for id, records := range prs.records {
		backup[id] = make([]PegRecord, len(records))
		copy(backup[id], records)
	}

	prs.logger.Println("Peg records backup created")
	return backup, nil
}

// RestorePegRecords restores peg records from a backup.
func (prs *PegRecordsService) RestorePegRecords(backup map[string][]PegRecord) error {
	prs.mutex.Lock()
	defer prs.mutex.Unlock()

	for id, records := range backup {
		prs.records[id] = make([]PegRecord, len(records))
		copy(prs.records[id], records)
	}

	prs.logger.Println("Peg records restored from backup")
	return nil
}

// LogPegRecords logs detailed information about all peg records.
func (prs *PegRecordsService) LogPegRecords() {
	prs.mutex.Lock()
	defer prs.mutex.Unlock()

	for assetID, records := range prs.records {
		prs.logger.Printf("PeggedAssetID: %s, Records: %v\n", assetID, records)
	}
}

// EncryptPegRecord encrypts a peg record.
func (prs *PegRecordsService) EncryptPegRecord(record PegRecord) ([]byte, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal record: %v", err)
	}

	encryptedData, err := crypto.EncryptAES(prs.encryptionKey, data)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt record: %v", err)
	}

	return encryptedData, nil
}

// DecryptPegRecord decrypts a peg record.
func (prs *PegRecordsService) DecryptPegRecord(encryptedData []byte) (PegRecord, error) {
	data, err := crypto.DecryptAES(prs.encryptionKey, encryptedData)
	if err != nil {
		return PegRecord{}, fmt.Errorf("failed to decrypt record: %v", err)
	}

	var record PegRecord
	err = json.Unmarshal(data, &record)
	if err != nil {
		return PegRecord{}, fmt.Errorf("failed to unmarshal record: %v", err)
	}

	return record, nil
}
