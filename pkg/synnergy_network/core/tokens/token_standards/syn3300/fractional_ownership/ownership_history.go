package fractional_ownership

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/encryption"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/ledger"
)

// OwnershipRecord represents an ownership change record for fractional shares
type OwnershipRecord struct {
	RecordID      string    `json:"record_id"`
	ETFID         string    `json:"etf_id"`
	ShareTokenID  string    `json:"share_token_id"`
	PreviousOwner string    `json:"previous_owner"`
	NewOwner      string    `json:"new_owner"`
	Fraction      float64   `json:"fraction"`
	Timestamp     time.Time `json:"timestamp"`
}

// OwnershipHistoryService provides methods to manage ownership history of fractional shares of ETFs
type OwnershipHistoryService struct {
	ledgerService     *ledger.LedgerService
	encryptionService *encryption.EncryptionService
}

// NewOwnershipHistoryService creates a new instance of OwnershipHistoryService
func NewOwnershipHistoryService(ledgerService *ledger.LedgerService, encryptionService *encryption.EncryptionService) *OwnershipHistoryService {
	return &OwnershipHistoryService{
		ledgerService:     ledgerService,
		encryptionService: encryptionService,
	}
}

// RecordOwnershipChange records a change in ownership for a fractional share of an ETF
func (s *OwnershipHistoryService) RecordOwnershipChange(etfID, shareTokenID, previousOwner, newOwner string, fraction float64) (*OwnershipRecord, error) {
	if etfID == "" || shareTokenID == "" || previousOwner == "" || newOwner == "" || fraction <= 0 || fraction > 1 {
		return nil, errors.New("invalid input parameters")
	}

	record := &OwnershipRecord{
		RecordID:      generateRecordID(etfID, shareTokenID, previousOwner, newOwner),
		ETFID:         etfID,
		ShareTokenID:  shareTokenID,
		PreviousOwner: previousOwner,
		NewOwner:      newOwner,
		Fraction:      fraction,
		Timestamp:     time.Now(),
	}

	// Encrypt the ownership record
	encryptedRecord, err := s.encryptionService.EncryptData(record)
	if err != nil {
		return nil, err
	}

	// Record the ownership change in the ledger
	if err := s.ledgerService.RecordOwnershipChange(encryptedRecord); err != nil {
		return nil, err
	}

	return record, nil
}

// GetOwnershipHistory retrieves the ownership history of a fractional share by its ETF ID and share token ID
func (s *OwnershipHistoryService) GetOwnershipHistory(etfID, shareTokenID string) ([]*OwnershipRecord, error) {
	if etfID == "" || shareTokenID == "" {
		return nil, errors.New("invalid input parameters")
	}

	// Retrieve the encrypted ownership history from the ledger
	encryptedRecords, err := s.ledgerService.GetOwnershipHistory(etfID, shareTokenID)
	if err != nil {
		return nil, err
	}

	var records []*OwnershipRecord
	for _, encryptedRecord := range encryptedRecords {
		record, err := s.encryptionService.DecryptData(encryptedRecord)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	return records, nil
}

// generateRecordID generates a unique record ID based on the ETF ID, share token ID, previous owner, and new owner
func generateRecordID(etfID, shareTokenID, previousOwner, newOwner string) string {
	data := etfID + shareTokenID + previousOwner + newOwner + time.Now().String()
	return hash(data)
}

// hash generates a hash of the given data
func hash(data string) string {
	hash := sha256.New()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

// EncryptionService handles encryption-related operations
type EncryptionService struct{}

// EncryptData encrypts the given data using the most secure method for the situation
func (e *EncryptionService) EncryptData(data interface{}) (string, error) {
	serializedData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	encryptedData, err := encryption.Argon2Encrypt(serializedData)
	if err != nil {
		return "", err
	}
	return encryptedData, nil
}

// DecryptData decrypts the given data using the most secure method for the situation
func (e *EncryptionService) DecryptData(encryptedData string) (*OwnershipRecord, error) {
	decryptedData, err := encryption.Argon2Decrypt(encryptedData)
	if err != nil {
		return nil, err
	}

	var record OwnershipRecord
	if err := json.Unmarshal([]byte(decryptedData), &record); err != nil {
		return nil, err
	}

	return &record, nil
}
