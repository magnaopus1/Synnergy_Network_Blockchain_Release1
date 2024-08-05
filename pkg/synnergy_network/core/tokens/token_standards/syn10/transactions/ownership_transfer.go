package transactions

import (
	"errors"
	"fmt"
	"log"

	"github.com/synnergy_network/syn10/ledger"
	"github.com/synnergy_network/syn10/security"
	"github.com/synnergy_network/syn10/validators"
)

// OwnershipTransfer represents a transfer of token ownership.
type OwnershipTransfer struct {
	TokenID        string
	SenderAddress  string
	ReceiverAddress string
	Amount         uint64
	VerificationID string
}

// OwnershipTransferProcessor handles the processing of ownership transfers.
type OwnershipTransferProcessor struct {
	ledger            *ledger.TokenLedger
	validator         *validators.TransferValidator
	encryptionService *security.EncryptionService
}

// NewOwnershipTransferProcessor initializes a new OwnershipTransferProcessor.
func NewOwnershipTransferProcessor(ledger *ledger.TokenLedger, validator *validators.TransferValidator, encryptionService *security.EncryptionService) *OwnershipTransferProcessor {
	return &OwnershipTransferProcessor{
		ledger:            ledger,
		validator:         validator,
		encryptionService: encryptionService,
	}
}

// TransferOwnership processes a token ownership transfer.
func (o *OwnershipTransferProcessor) TransferOwnership(transfer OwnershipTransfer) error {
	// Validate the transfer details
	if err := o.validateTransfer(transfer); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Encrypt verification ID
	encryptedVerificationID, err := o.encryptionService.Encrypt([]byte(transfer.VerificationID))
	if err != nil {
		return fmt.Errorf("failed to encrypt verification ID: %w", err)
	}

	// Perform the transfer on the ledger
	if err := o.ledger.TransferTokens(transfer.TokenID, transfer.SenderAddress, transfer.ReceiverAddress, transfer.Amount); err != nil {
		return fmt.Errorf("ledger update failed: %w", err)
	}

	// Log the ownership transfer
	if err := o.ledger.LogOwnershipTransfer(transfer.TokenID, transfer.SenderAddress, transfer.ReceiverAddress, transfer.Amount, string(encryptedVerificationID)); err != nil {
		return fmt.Errorf("failed to log ownership transfer: %w", err)
	}

	return nil
}

// validateTransfer validates the ownership transfer.
func (o *OwnershipTransferProcessor) validateTransfer(transfer OwnershipTransfer) error {
	if err := o.validator.ValidateOwnership(transfer.TokenID, transfer.SenderAddress, transfer.Amount); err != nil {
		return fmt.Errorf("ownership validation failed: %w", err)
	}
	if err := o.validator.ValidateTransfer(transfer.TokenID, transfer.SenderAddress, transfer.ReceiverAddress, transfer.Amount); err != nil {
		return fmt.Errorf("transfer validation failed: %w", err)
	}
	return nil
}

// CreateTransfer creates a new OwnershipTransfer instance.
func (o *OwnershipTransferProcessor) CreateTransfer(tokenID, senderAddress, receiverAddress, verificationID string, amount uint64) OwnershipTransfer {
	return OwnershipTransfer{
		TokenID:         tokenID,
		SenderAddress:   senderAddress,
		ReceiverAddress: receiverAddress,
		VerificationID:  verificationID,
		Amount:          amount,
	}
}

// DecryptVerificationID decrypts the verification ID for an ownership transfer.
func (o *OwnershipTransferProcessor) DecryptVerificationID(encryptedData string) (string, error) {
	decryptedData, err := o.encryptionService.Decrypt([]byte(encryptedData))
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}
	return string(decryptedData), nil
}

// OwnershipHistory retrieves the ownership history of a token.
func (o *OwnershipTransferProcessor) OwnershipHistory(tokenID string) ([]ledger.OwnershipRecord, error) {
	history, err := o.ledger.GetOwnershipHistory(tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve ownership history: %w", err)
	}
	return history, nil
}

// RollbackTransfer attempts to rollback a transfer in case of an error.
func (o *OwnershipTransferProcessor) RollbackTransfer(transfer OwnershipTransfer) error {
	log.Printf("Attempting to rollback transfer for TokenID: %s", transfer.TokenID)

	// Perform the rollback on the ledger
	if err := o.ledger.ReverseTransfer(transfer.TokenID, transfer.ReceiverAddress, transfer.SenderAddress, transfer.Amount); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	log.Printf("Rollback successful for TokenID: %s", transfer.TokenID)
	return nil
}

// OwnershipVerification verifies the current ownership of a token.
func (o *OwnershipTransferProcessor) OwnershipVerification(tokenID, address string) (bool, error) {
	isOwner, err := o.ledger.VerifyOwnership(tokenID, address)
	if err != nil {
		return false, fmt.Errorf("ownership verification failed: %w", err)
	}
	return isOwner, nil
}
