package factory

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/encryption"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3300/transactions"
)

// TokenFactoryService provides methods to create and manage SYN3300 tokens
type TokenFactoryService struct {
	ledgerService     *ledger.LedgerService
	encryptionService *encryption.EncryptionService
	transactionService *transactions.TransactionService
}

// NewTokenFactoryService creates a new instance of TokenFactoryService
func NewTokenFactoryService(ledgerService *ledger.LedgerService, encryptionService *encryption.EncryptionService, transactionService *transactions.TransactionService) *TokenFactoryService {
	return &TokenFactoryService{
		ledgerService:     ledgerService,
		encryptionService: encryptionService,
		transactionService: transactionService,
	}
}

// CreateToken creates a new SYN3300 token representing an ETF
func (s *TokenFactoryService) CreateToken(etfID, name string, totalShares int, currentPrice float64) (*assets.ETFMetadata, error) {
	if etfID == "" || name == "" || totalShares <= 0 || currentPrice <= 0 {
		return nil, errors.New("invalid input parameters")
	}

	// Create ETF Metadata
	metadata := &assets.ETFMetadata{
		ETFID:         etfID,
		Name:          name,
		TotalShares:   totalShares,
		AvailableShares: totalShares,
		CurrentPrice:  currentPrice,
		Timestamp:     time.Now(),
	}

	// Encrypt the metadata
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

// MintShares mints new shares for an existing ETF token
func (s *TokenFactoryService) MintShares(etfID string, additionalShares int) (*assets.ETFMetadata, error) {
	if etfID == "" || additionalShares <= 0 {
		return nil, errors.New("invalid input parameters")
	}

	// Retrieve the existing metadata
	metadata, err := s.ledgerService.GetETFMetadata(etfID)
	if err != nil {
		return nil, err
	}

	// Update the share count
	metadata.TotalShares += additionalShares
	metadata.AvailableShares += additionalShares
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

// BurnShares burns existing shares of an ETF token
func (s *TokenFactoryService) BurnShares(etfID string, sharesToBurn int) (*assets.ETFMetadata, error) {
	if etfID == "" || sharesToBurn <= 0 {
		return nil, errors.New("invalid input parameters")
	}

	// Retrieve the existing metadata
	metadata, err := s.ledgerService.GetETFMetadata(etfID)
	if err != nil {
		return nil, err
	}

	// Update the share count
	if metadata.AvailableShares < sharesToBurn {
		return nil, errors.New("insufficient shares to burn")
	}
	metadata.TotalShares -= sharesToBurn
	metadata.AvailableShares -= sharesToBurn
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

// TransferShares transfers shares from one owner to another
func (s *TokenFactoryService) TransferShares(etfID, fromOwner, toOwner string, shares int) error {
	if etfID == "" || fromOwner == "" || toOwner == "" || shares <= 0 {
		return errors.New("invalid input parameters")
	}

	// Validate the transfer in the ledger
	if err := s.ledgerService.ValidateTransfer(etfID, fromOwner, toOwner, shares); err != nil {
		return err
	}

	// Create a transaction for the transfer
	transaction := &transactions.Transaction{
		ETFID:     etfID,
		FromOwner: fromOwner,
		ToOwner:   toOwner,
		Shares:    shares,
		Timestamp: time.Now(),
	}

	// Encrypt the transaction
	encryptedTransaction, err := s.encryptionService.EncryptData(transaction)
	if err != nil {
		return err
	}

	// Record the transaction in the ledger
	if err := s.ledgerService.RecordTransaction(encryptedTransaction); err != nil {
		return err
	}

	return nil
}
