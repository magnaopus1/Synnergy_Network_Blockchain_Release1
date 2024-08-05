package fractional_ownership

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/encryption"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/ledger"
)

// ShareTrackingRecord represents a record of fractional share tracking
type ShareTrackingRecord struct {
	RecordID      string    `json:"record_id"`
	ETFID         string    `json:"etf_id"`
	ShareTokenID  string    `json:"share_token_id"`
	Owner         string    `json:"owner"`
	Fraction      float64   `json:"fraction"`
	LastUpdated   time.Time `json:"last_updated"`
	TransactionID string    `json:"transaction_id"`
}

// ShareTrackingService provides methods to track fractional shares of ETFs
type ShareTrackingService struct {
	ledgerService     *ledger.LedgerService
	encryptionService *encryption.EncryptionService
}

// NewShareTrackingService creates a new instance of ShareTrackingService
func NewShareTrackingService(ledgerService *ledger.LedgerService, encryptionService *encryption.EncryptionService) *ShareTrackingService {
	return &ShareTrackingService{
		ledgerService:     ledgerService,
		encryptionService: encryptionService,
	}
}

// TrackShare records the tracking information of a fractional share
func (s *ShareTrackingService) TrackShare(etfID, shareTokenID, owner string, fraction float64, transactionID string) (*ShareTrackingRecord, error) {
	if etfID == "" || shareTokenID == "" || owner == "" || fraction <= 0 || fraction > 1 || transactionID == "" {
		return nil, errors.New("invalid input parameters")
	}

	record := &ShareTrackingRecord{
		RecordID:      generateRecordID(etfID, shareTokenID, owner, transactionID),
		ETFID:         etfID,
		ShareTokenID:  shareTokenID,
		Owner:         owner,
		Fraction:      fraction,
		LastUpdated:   time.Now(),
		TransactionID: transactionID,
	}

	// Encrypt the share tracking record
	encryptedRecord, err := s.encryptionService.EncryptData(record)
	if err != nil {
		return nil, err
	}

	// Record the share tracking in the ledger
	if err := s.ledgerService.RecordShareTracking(encryptedRecord); err != nil {
		return nil, err
	}

	return record, nil
}

// GetShareTrackingHistory retrieves the tracking history of a fractional share by its ETF ID and share token ID
func (s *ShareTrackingService) GetShareTrackingHistory(etfID, shareTokenID string) ([]*ShareTrackingRecord, error) {
	if etfID == "" || shareTokenID == "" {
		return nil, errors.New("invalid input parameters")
	}

	// Retrieve the encrypted share tracking history from the ledger
	encryptedRecords, err := s.ledgerService.GetShareTrackingHistory(etfID, shareTokenID)
	if err != nil {
		return nil, err
	}

	var records []*ShareTrackingRecord
	for _, encryptedRecord := range encryptedRecords {
		record, err := s.encryptionService.DecryptData(encryptedRecord)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	return records, nil
}

// generateRecordID generates a unique record ID based on the ETF ID, share token ID, owner, and transaction ID
func generateRecordID(etfID, shareTokenID, owner, transactionID string) string {
	data := etfID + shareTokenID + owner + transactionID + time.Now().String()
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
func (e *EncryptionService) DecryptData(encryptedData string) (*ShareTrackingRecord, error) {
	decryptedData, err := encryption.Argon2Decrypt(encryptedData)
	if err != nil {
		return nil, err
	}

	var record ShareTrackingRecord
	if err := json.Unmarshal([]byte(decryptedData), &record); err != nil {
		return nil, err
	}

	return &record, nil
}
