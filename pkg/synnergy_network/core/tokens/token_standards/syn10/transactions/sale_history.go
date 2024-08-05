package transactions

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/synnergy_network/syn10/ledger"
	"github.com/synnergy_network/syn10/security"
	"github.com/synnergy_network/syn10/validators"
)

// SaleRecord represents a record of a token sale transaction.
type SaleRecord struct {
	TokenID       string
	SellerAddress string
	BuyerAddress  string
	Amount        uint64
	SalePrice     float64
	Timestamp     time.Time
	TransactionID string
}

// SaleHistoryProcessor handles the processing and storage of sale history records.
type SaleHistoryProcessor struct {
	ledger            *ledger.TokenLedger
	validator         *validators.SaleValidator
	encryptionService *security.EncryptionService
}

// NewSaleHistoryProcessor initializes a new SaleHistoryProcessor.
func NewSaleHistoryProcessor(ledger *ledger.TokenLedger, validator *validators.SaleValidator, encryptionService *security.EncryptionService) *SaleHistoryProcessor {
	return &SaleHistoryProcessor{
		ledger:            ledger,
		validator:         validator,
		encryptionService: encryptionService,
	}
}

// RecordSale logs a new sale transaction to the ledger.
func (s *SaleHistoryProcessor) RecordSale(record SaleRecord) error {
	// Validate the sale details
	if err := s.validateSale(record); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Encrypt the transaction ID for additional security
	encryptedTransactionID, err := s.encryptionService.Encrypt([]byte(record.TransactionID))
	if err != nil {
		return fmt.Errorf("failed to encrypt transaction ID: %w", err)
	}

	// Log the sale record on the ledger
	if err := s.ledger.LogSaleRecord(record.TokenID, record.SellerAddress, record.BuyerAddress, record.Amount, record.SalePrice, record.Timestamp, string(encryptedTransactionID)); err != nil {
		return fmt.Errorf("failed to log sale record: %w", err)
	}

	return nil
}

// validateSale validates the sale record to ensure all conditions are met.
func (s *SaleHistoryProcessor) validateSale(record SaleRecord) error {
	if err := s.validator.ValidateSeller(record.TokenID, record.SellerAddress); err != nil {
		return fmt.Errorf("seller validation failed: %w", err)
	}
	if err := s.validator.ValidateBuyer(record.BuyerAddress); err != nil {
		return fmt.Errorf("buyer validation failed: %w", err)
	}
	if err := s.validator.ValidateSalePrice(record.SalePrice); err != nil {
		return fmt.Errorf("sale price validation failed: %w", err)
	}
	if err := s.validator.ValidateTransaction(record.TransactionID); err != nil {
		return fmt.Errorf("transaction validation failed: %w", err)
	}
	return nil
}

// RetrieveSaleHistory retrieves the sale history for a specific token.
func (s *SaleHistoryProcessor) RetrieveSaleHistory(tokenID string) ([]SaleRecord, error) {
	history, err := s.ledger.GetSaleHistory(tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve sale history: %w", err)
	}
	return history, nil
}

// DecryptTransactionID decrypts the transaction ID for a sale record.
func (s *SaleHistoryProcessor) DecryptTransactionID(encryptedData string) (string, error) {
	decryptedData, err := s.encryptionService.Decrypt([]byte(encryptedData))
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}
	return string(decryptedData), nil
}

// GenerateSalesReport generates a detailed report of sales within a specified period.
func (s *SaleHistoryProcessor) GenerateSalesReport(startTime, endTime time.Time) ([]SaleRecord, error) {
	sales, err := s.ledger.GetSalesWithinPeriod(startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("failed to generate sales report: %w", err)
	}
	return sales, nil
}

// RollbackSale attempts to rollback a sale in case of an error.
func (s *SaleHistoryProcessor) RollbackSale(record SaleRecord) error {
	log.Printf("Attempting to rollback sale for TokenID: %s", record.TokenID)

	// Perform the rollback on the ledger
	if err := s.ledger.ReverseSale(record.TokenID, record.BuyerAddress, record.SellerAddress, record.Amount); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	log.Printf("Rollback successful for TokenID: %s", record.TokenID)
	return nil
}
