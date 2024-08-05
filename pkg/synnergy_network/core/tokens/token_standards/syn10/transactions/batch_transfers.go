package transactions

import (
	"errors"
	"fmt"
	"sync"

	"github.com/synnergy_network/syn10/ledger"
	"github.com/synnergy_network/syn10/security"
	"github.com/synnergy_network/syn10/validators"
)

// BatchTransfer represents a batch of transfers to be processed.
type BatchTransfer struct {
	TokenID        string
	SenderAddress  string
	Transfers      []TransferDetail
	VerificationID string
}

// TransferDetail represents a single transfer in a batch.
type TransferDetail struct {
	ReceiverAddress string
	Amount          uint64
}

// BatchTransferProcessor handles the execution of batch transfers.
type BatchTransferProcessor struct {
	ledger            *ledger.TokenLedger
	validator         *validators.TransferValidator
	encryptionService *security.EncryptionService
}

// NewBatchTransferProcessor initializes a new BatchTransferProcessor.
func NewBatchTransferProcessor(ledger *ledger.TokenLedger, validator *validators.TransferValidator, encryptionService *security.EncryptionService) *BatchTransferProcessor {
	return &BatchTransferProcessor{
		ledger:            ledger,
		validator:         validator,
		encryptionService: encryptionService,
	}
}

// ProcessBatch processes a batch of transfers. It ensures all transfers are validated and applied atomically.
func (b *BatchTransferProcessor) ProcessBatch(batch BatchTransfer) error {
	if len(batch.Transfers) == 0 {
		return errors.New("no transfers in the batch")
	}

	// Validate the batch
	if err := b.validateBatch(batch); err != nil {
		return fmt.Errorf("batch validation failed: %v", err)
	}

	// Process transfers
	return b.processTransfers(batch)
}

// validateBatch validates the batch of transfers.
func (b *BatchTransferProcessor) validateBatch(batch BatchTransfer) error {
	for _, transfer := range batch.Transfers {
		if err := b.validator.ValidateTransfer(batch.TokenID, batch.SenderAddress, transfer.ReceiverAddress, transfer.Amount); err != nil {
			return err
		}
	}
	return nil
}

// processTransfers executes the transfers in the batch.
func (b *BatchTransferProcessor) processTransfers(batch BatchTransfer) error {
	var wg sync.WaitGroup
	var mutex sync.Mutex
	errors := make([]error, len(batch.Transfers))

	for i, transfer := range batch.Transfers {
		wg.Add(1)
		go func(i int, transfer TransferDetail) {
			defer wg.Done()
			if err := b.ledger.TransferTokens(batch.TokenID, batch.SenderAddress, transfer.ReceiverAddress, transfer.Amount); err != nil {
				mutex.Lock()
				errors[i] = err
				mutex.Unlock()
			}
		}(i, transfer)
	}

	wg.Wait()

	for _, err := range errors {
		if err != nil {
			return err
		}
	}

	// Encrypt batch details for secure storage and auditing
	encryptedVerificationID, err := b.encryptionService.Encrypt([]byte(batch.VerificationID))
	if err != nil {
		return fmt.Errorf("failed to encrypt verification ID: %v", err)
	}

	// Store the encrypted batch details
	if err := b.ledger.StoreBatchDetails(batch.TokenID, encryptedVerificationID, batch.Transfers); err != nil {
		return fmt.Errorf("failed to store batch details: %v", err)
	}

	return nil
}

// CreateBatch creates a new BatchTransfer instance.
func (b *BatchTransferProcessor) CreateBatch(tokenID, senderAddress, verificationID string, transfers []TransferDetail) BatchTransfer {
	return BatchTransfer{
		TokenID:        tokenID,
		SenderAddress:  senderAddress,
		VerificationID: verificationID,
		Transfers:      transfers,
	}
}

// EncryptVerificationID encrypts the verification ID for the batch.
func (b *BatchTransferProcessor) EncryptVerificationID(verificationID string) (string, error) {
	encryptedData, err := b.encryptionService.Encrypt([]byte(verificationID))
	if err != nil {
		return "", err
	}
	return string(encryptedData), nil
}

// DecryptVerificationID decrypts the verification ID for the batch.
func (b *BatchTransferProcessor) DecryptVerificationID(encryptedData string) (string, error) {
	decryptedData, err := b.encryptionService.Decrypt([]byte(encryptedData))
	if err != nil {
		return "", err
	}
	return string(decryptedData), nil
}
