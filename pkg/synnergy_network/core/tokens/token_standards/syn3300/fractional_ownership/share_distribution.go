package fractional_ownership

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/encryption"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/ledger"
)

// ShareDistributionRecord represents a record of share distribution
type ShareDistributionRecord struct {
	RecordID     string    `json:"record_id"`
	ETFID        string    `json:"etf_id"`
	ShareTokenID string    `json:"share_token_id"`
	Recipient    string    `json:"recipient"`
	Fraction     float64   `json:"fraction"`
	Timestamp    time.Time `json:"timestamp"`
}

// ShareDistributionService provides methods to manage share distribution of fractional shares of ETFs
type ShareDistributionService struct {
	ledgerService     *ledger.LedgerService
	encryptionService *encryption.EncryptionService
}

// NewShareDistributionService creates a new instance of ShareDistributionService
func NewShareDistributionService(ledgerService *ledger.LedgerService, encryptionService *encryption.EncryptionService) *ShareDistributionService {
	return &ShareDistributionService{
		ledgerService:     ledgerService,
		encryptionService: encryptionService,
	}
}

// DistributeShares distributes fractional shares of an ETF to a recipient
func (s *ShareDistributionService) DistributeShares(etfID, shareTokenID, recipient string, fraction float64) (*ShareDistributionRecord, error) {
	if etfID == "" || shareTokenID == "" || recipient == "" || fraction <= 0 || fraction > 1 {
		return nil, errors.New("invalid input parameters")
	}

	record := &ShareDistributionRecord{
		RecordID:     generateRecordID(etfID, shareTokenID, recipient),
		ETFID:        etfID,
		ShareTokenID: shareTokenID,
		Recipient:    recipient,
		Fraction:     fraction,
		Timestamp:    time.Now(),
	}

	// Encrypt the share distribution record
	encryptedRecord, err := s.encryptionService.EncryptData(record)
	if err != nil {
		return nil, err
	}

	// Record the share distribution in the ledger
	if err := s.ledgerService.RecordShareDistribution(encryptedRecord); err != nil {
		return nil, err
	}

	return record, nil
}

// GetShareDistributionHistory retrieves the share distribution history of a fractional share by its ETF ID and share token ID
func (s *ShareDistributionService) GetShareDistributionHistory(etfID, shareTokenID string) ([]*ShareDistributionRecord, error) {
	if etfID == "" || shareTokenID == "" {
		return nil, errors.New("invalid input parameters")
	}

	// Retrieve the encrypted share distribution history from the ledger
	encryptedRecords, err := s.ledgerService.GetShareDistributionHistory(etfID, shareTokenID)
	if err != nil {
		return nil, err
	}

	var records []*ShareDistributionRecord
	for _, encryptedRecord := range encryptedRecords {
		record, err := s.encryptionService.DecryptData(encryptedRecord)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	return records, nil
}

// generateRecordID generates a unique record ID based on the ETF ID, share token ID, and recipient
func generateRecordID(etfID, shareTokenID, recipient string) string {
	data := etfID + shareTokenID + recipient + time.Now().String()
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
func (e *EncryptionService) DecryptData(encryptedData string) (*ShareDistributionRecord, error) {
	decryptedData, err := encryption.Argon2Decrypt(encryptedData)
	if err != nil {
		return nil, err
	}

	var record ShareDistributionRecord
	if err := json.Unmarshal([]byte(decryptedData), &record); err != nil {
		return nil, err
	}

	return &record, nil
}
