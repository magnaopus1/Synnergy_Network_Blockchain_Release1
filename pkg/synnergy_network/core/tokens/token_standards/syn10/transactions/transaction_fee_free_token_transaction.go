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

// TransactionFeeFree represents a fee-free transaction of tokens.
type TransactionFeeFree struct {
	TokenID       string
	FromAddress   string
	ToAddress     string
	Amount        uint64
	Timestamp     time.Time
	TransactionID string
}

// FeeFreeTransactionProcessor handles fee-free token transactions.
type FeeFreeTransactionProcessor struct {
	ledger            *ledger.TokenLedger
	validator         *validators.TransactionValidator
	encryptionService *security.EncryptionService
}

// NewFeeFreeTransactionProcessor initializes a new FeeFreeTransactionProcessor.
func NewFeeFreeTransactionProcessor(ledger *ledger.TokenLedger, validator *validators.TransactionValidator, encryptionService *security.EncryptionService) *FeeFreeTransactionProcessor {
	return &FeeFreeTransactionProcessor{
		ledger:            ledger,
		validator:         validator,
		encryptionService: encryptionService,
	}
}

// ProcessTransaction processes a fee-free token transaction.
func (p *FeeFreeTransactionProcessor) ProcessTransaction(tx TransactionFeeFree) error {
	// Validate the transaction
	if err := p.validateTransaction(tx); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Encrypt the transaction ID for additional security
	encryptedTransactionID, err := p.encryptionService.Encrypt([]byte(tx.TransactionID))
	if err != nil {
		return fmt.Errorf("failed to encrypt transaction ID: %w", err)
	}

	// Record the transaction in the ledger
	if err := p.ledger.RecordTransaction(tx.TokenID, tx.FromAddress, tx.ToAddress, tx.Amount, tx.Timestamp, string(encryptedTransactionID), true); err != nil {
		return fmt.Errorf("failed to record transaction: %w", err)
	}

	return nil
}

// validateTransaction ensures that the transaction meets all necessary criteria.
func (p *FeeFreeTransactionProcessor) validateTransaction(tx TransactionFeeFree) error {
	if err := p.validator.ValidateSender(tx.FromAddress); err != nil {
		return fmt.Errorf("sender validation failed: %w", err)
	}
	if err := p.validator.ValidateReceiver(tx.ToAddress); err != nil {
		return fmt.Errorf("receiver validation failed: %w", err)
	}
	if err := p.validator.ValidateAmount(tx.Amount); err != nil {
		return fmt.Errorf("amount validation failed: %w", err)
	}
	if err := p.validator.ValidateTransactionID(tx.TransactionID); err != nil {
		return fmt.Errorf("transaction ID validation failed: %w", err)
	}
	return nil
}

// RetrieveTransaction retrieves a fee-free transaction by its transaction ID.
func (p *FeeFreeTransactionProcessor) RetrieveTransaction(transactionID string) (*TransactionFeeFree, error) {
	encryptedTransactionID, err := p.encryptionService.Encrypt([]byte(transactionID))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt transaction ID: %w", err)
	}

	tx, err := p.ledger.GetTransactionByID(string(encryptedTransactionID))
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve transaction: %w", err)
	}

	return &TransactionFeeFree{
		TokenID:       tx.TokenID,
		FromAddress:   tx.FromAddress,
		ToAddress:     tx.ToAddress,
		Amount:        tx.Amount,
		Timestamp:     tx.Timestamp,
		TransactionID: transactionID,
	}, nil
}

// ReverseTransaction rolls back a fee-free transaction in case of errors or disputes.
func (p *FeeFreeTransactionProcessor) ReverseTransaction(tx TransactionFeeFree) error {
	log.Printf("Attempting to reverse transaction for TokenID: %s", tx.TokenID)

	// Perform the reversal on the ledger
	if err := p.ledger.ReverseTransaction(tx.TokenID, tx.FromAddress, tx.ToAddress, tx.Amount); err != nil {
		return fmt.Errorf("transaction reversal failed: %w", err)
	}

	log.Printf("Transaction reversal successful for TokenID: %s", tx.TokenID)
	return nil
}
