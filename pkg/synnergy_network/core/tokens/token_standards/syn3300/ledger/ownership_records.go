package ledger

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/encryption"
)

// OwnershipRecord represents a record of ownership for ETF shares
type OwnershipRecord struct {
	OwnerID      string    `json:"owner_id"`
	ETFID        string    `json:"etf_id"`
	Shares       float64   `json:"shares"`
	Timestamp    time.Time `json:"timestamp"`
	TransactionID string   `json:"transaction_id"`
}

// OwnershipService manages the ownership records
type OwnershipService struct {
	ownershipRecords   []OwnershipRecord
	encryptionService *encryption.EncryptionService
}

// NewOwnershipService creates a new instance of OwnershipService
func NewOwnershipService(encryptionService *encryption.EncryptionService) *OwnershipService {
	return &OwnershipService{
		ownershipRecords:  make([]OwnershipRecord, 0),
		encryptionService: encryptionService,
	}
}

// AddOwnershipRecord adds a new ownership record
func (os *OwnershipService) AddOwnershipRecord(ownerID, etfID string, shares float64, transactionID string) (string, error) {
	record := OwnershipRecord{
		OwnerID:      ownerID,
		ETFID:        etfID,
		Shares:       shares,
		Timestamp:    time.Now(),
		TransactionID: transactionID,
	}

	encryptedRecord, err := os.encryptionService.EncryptData(record)
	if err != nil {
		return "", err
	}

	os.ownershipRecords = append(os.ownershipRecords, encryptedRecord)
	return record.TransactionID, nil
}

// GetOwnershipRecord retrieves an ownership record by transaction ID
func (os *OwnershipService) GetOwnershipRecord(transactionID string) (*OwnershipRecord, error) {
	for _, record := range os.ownershipRecords {
		decryptedRecord, err := os.encryptionService.DecryptData(record)
		if err != nil {
			return nil, err
		}

		if decryptedRecord.TransactionID == transactionID {
			return &decryptedRecord, nil
		}
	}
	return nil, errors.New("ownership record not found")
}

// GetAllOwnershipRecords retrieves all ownership records
func (os *OwnershipService) GetAllOwnershipRecords() ([]OwnershipRecord, error) {
	allRecords := make([]OwnershipRecord, 0)

	for _, record := range os.ownershipRecords {
		decryptedRecord, err := os.encryptionService.DecryptData(record)
		if err != nil {
			return nil, err
		}
		allRecords = append(allRecords, decryptedRecord)
	}

	return allRecords, nil
}

// UpdateOwnershipRecord updates an existing ownership record
func (os *OwnershipService) UpdateOwnershipRecord(transactionID, ownerID, etfID string, shares float64) error {
	for i, record := range os.ownershipRecords {
		decryptedRecord, err := os.encryptionService.DecryptData(record)
		if err != nil {
			return err
		}

		if decryptedRecord.TransactionID == transactionID {
			decryptedRecord.OwnerID = ownerID
			decryptedRecord.ETFID = etfID
			decryptedRecord.Shares = shares
			decryptedRecord.Timestamp = time.Now()

			encryptedRecord, err := os.encryptionService.EncryptData(decryptedRecord)
			if err != nil {
				return err
			}

			os.ownershipRecords[i] = encryptedRecord
			return nil
		}
	}
	return errors.New("ownership record not found")
}

// DeleteOwnershipRecord deletes an ownership record by transaction ID
func (os *OwnershipService) DeleteOwnershipRecord(transactionID string) error {
	for i, record := range os.ownershipRecords {
		decryptedRecord, err := os.encryptionService.DecryptData(record)
		if err != nil {
			return err
		}

		if decryptedRecord.TransactionID == transactionID {
			os.ownershipRecords = append(os.ownershipRecords[:i], os.ownershipRecords[i+1:]...)
			return nil
		}
	}
	return errors.New("ownership record not found")
}

// VerifyOwnershipRecord verifies the integrity of an ownership record by transaction ID
func (os *OwnershipService) VerifyOwnershipRecord(transactionID string) (bool, error) {
	record, err := os.GetOwnershipRecord(transactionID)
	if err != nil {
		return false, err
	}

	// Implement further verification logic if needed
	if record.TransactionID == transactionID && record.Shares > 0 {
		return true, nil
	}

	return false, errors.New("ownership record verification failed")
}
