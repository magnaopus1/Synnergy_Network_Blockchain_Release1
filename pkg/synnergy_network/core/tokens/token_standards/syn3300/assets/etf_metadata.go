package assets

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/encryption"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/transactions"
)

// ETFMetadata represents the metadata of an ETF
type ETFMetadata struct {
	ETFID         string    `json:"etf_id"`
	Name          string    `json:"name"`
	TotalShares   int       `json:"total_shares"`
	AvailableShares int     `json:"available_shares"`
	CurrentPrice  float64   `json:"current_price"`
	Timestamp     time.Time `json:"timestamp"`
}

// ETFMetadataService provides methods to manage ETF metadata
type ETFMetadataService struct {
	ledgerService *ledger.LedgerService
	encryptionService *EncryptionService
}

// NewETFMetadataService creates a new instance of ETFMetadataService
func NewETFMetadataService(ledgerService *ledger.LedgerService, encryptionService *EncryptionService) *ETFMetadataService {
	return &ETFMetadataService{ledgerService: ledgerService, encryptionService: encryptionService}
}

// CreateETFMetadata creates a new ETF metadata record
func (s *ETFMetadataService) CreateETFMetadata(etfID, name string, totalShares, availableShares int, currentPrice float64) (*ETFMetadata, error) {
	// Validate inputs
	if etfID == "" || name == "" || totalShares <= 0 || availableShares < 0 || currentPrice <= 0 {
		return nil, errors.New("invalid input parameters")
	}

	// Create a new ETF metadata
	metadata := &ETFMetadata{
		ETFID:          etfID,
		Name:           name,
		TotalShares:    totalShares,
		AvailableShares: availableShares,
		CurrentPrice:   currentPrice,
		Timestamp:      time.Now(),
	}

	// Encrypt sensitive data
	encryptedMetadata, err := s.encryptionService.EncryptData(metadata)
	if err != nil {
		return nil, err
	}

	// Record the metadata in the ledger
	if err := s.ledgerService.RecordETFMetadata(encryptedMetadata); err != nil {
		return nil, err
	}

	return metadata, nil
}

// UpdateETFMetadata updates an existing ETF metadata record
func (s *ETFMetadataService) UpdateETFMetadata(etfID string, availableShares int, currentPrice float64) (*ETFMetadata, error) {
	// Validate inputs
	if etfID == "" || availableShares < 0 || currentPrice <= 0 {
		return nil, errors.New("invalid input parameters")
	}

	// Retrieve the existing metadata from the ledger
	metadata, err := s.ledgerService.GetETFMetadata(etfID)
	if err != nil {
		return nil, err
	}

	// Update the metadata fields
	metadata.AvailableShares = availableShares
	metadata.CurrentPrice = currentPrice
	metadata.Timestamp = time.Now()

	// Encrypt the updated metadata
	encryptedMetadata, err := s.encryptionService.EncryptData(metadata)
	if err != nil {
		return nil, err
	}

	// Update the metadata in the ledger
	if err := s.ledgerService.UpdateETFMetadata(etfID, encryptedMetadata); err != nil {
		return nil, err
	}

	return metadata, nil
}

// GetETFMetadata retrieves the metadata of an ETF by its ID
func (s *ETFMetadataService) GetETFMetadata(etfID string) (*ETFMetadata, error) {
	// Validate input
	if etfID == "" {
		return nil, errors.New("invalid input parameters")
	}

	// Retrieve the encrypted metadata from the ledger
	encryptedMetadata, err := s.ledgerService.GetETFMetadata(etfID)
	if err != nil {
		return nil, err
	}

	// Decrypt the metadata
	metadata, err := s.encryptionService.DecryptData(encryptedMetadata)
	if err != nil {
		return nil, err
	}

	return metadata, nil
}

// EncryptionService handles encryption-related operations
type EncryptionService struct{}

// EncryptData encrypts the given data using the most secure method for the situation
func (e *EncryptionService) EncryptData(data interface{}) (string, error) {
	// Use Argon2 for encryption
	serializedData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	encryptedData, err := encryption.Argon2Encrypt(string(serializedData))
	if err != nil {
		return "", err
	}
	return encryptedData, nil
}

// DecryptData decrypts the given data using the most secure method for the situation
func (e *EncryptionService) DecryptData(encryptedData string) (*ETFMetadata, error) {
	// Use Argon2 for decryption
	decryptedData, err := encryption.Argon2Decrypt(encryptedData)
	if err != nil {
		return nil, err
	}

	var metadata ETFMetadata
	if err := json.Unmarshal([]byte(decryptedData), &metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}
