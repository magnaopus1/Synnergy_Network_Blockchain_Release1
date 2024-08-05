package transactions

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"synnergy_network/core/tokens/token_standards/syn12/ledger"
	"synnergy_network/core/tokens/token_standards/syn12/storage"
	"synnergy_network/core/tokens/token_standards/syn12/utils"
)

// OwnershipTransferManager handles the transfer of T-Bill token ownership.
type OwnershipTransferManager struct {
	ledger          *ledger.OwnershipRecords
	transactionLock sync.Mutex
	storageManager  *storage.StorageManager
}

// NewOwnershipTransferManager creates a new OwnershipTransferManager.
func NewOwnershipTransferManager(ledger *ledger.OwnershipRecords, storageManager *storage.StorageManager) *OwnershipTransferManager {
	return &OwnershipTransferManager{
		ledger:         ledger,
		storageManager: storageManager,
	}
}

// TransferOwnership transfers the ownership of a T-Bill token from one party to another.
func (otm *OwnershipTransferManager) TransferOwnership(tokenID, from, to string) error {
	otm.transactionLock.Lock()
	defer otm.transactionLock.Unlock()

	// Verify the current ownership
	currentOwner, err := otm.ledger.GetOwner(tokenID)
	if err != nil {
		return fmt.Errorf("failed to get current owner: %v", err)
	}

	if currentOwner != from {
		return errors.New("ownership verification failed: token does not belong to the sender")
	}

	// Transfer the ownership
	if err := otm.ledger.UpdateOwner(tokenID, to); err != nil {
		return fmt.Errorf("failed to update ownership: %v", err)
	}

	// Log the transaction
	txnRecord := ledger.TransactionRecord{
		TokenID:      tokenID,
		From:         from,
		To:           to,
		Timestamp:    time.Now().UTC(),
		TransactionType: "Ownership Transfer",
	}

	if err := otm.ledger.RecordTransaction(txnRecord); err != nil {
		return fmt.Errorf("failed to record transaction: %v", err)
	}

	// Store the transaction record
	if err := otm.storageManager.SaveData(fmt.Sprintf("txn_%s", tokenID), txnRecord); err != nil {
		return fmt.Errorf("failed to store transaction record: %v", err)
	}

	return nil
}

// RevokeOwnership revokes the ownership of a T-Bill token.
func (otm *OwnershipTransferManager) RevokeOwnership(tokenID, owner string) error {
	otm.transactionLock.Lock()
	defer otm.transactionLock.Unlock()

	// Verify the current ownership
	currentOwner, err := otm.ledger.GetOwner(tokenID)
	if err != nil {
		return fmt.Errorf("failed to get current owner: %v", err)
	}

	if currentOwner != owner {
		return errors.New("ownership verification failed: token does not belong to the specified owner")
	}

	// Revoke the ownership (transfer to a null address or similar mechanism)
	nullAddress := "0x0000000000000000000000000000000000000000"
	if err := otm.ledger.UpdateOwner(tokenID, nullAddress); err != nil {
		return fmt.Errorf("failed to update ownership: %v", err)
	}

	// Log the revocation
	txnRecord := ledger.TransactionRecord{
		TokenID:      tokenID,
		From:         owner,
		To:           nullAddress,
		Timestamp:    time.Now().UTC(),
		TransactionType: "Ownership Revocation",
	}

	if err := otm.ledger.RecordTransaction(txnRecord); err != nil {
		return fmt.Errorf("failed to record transaction: %v", err)
	}

	// Store the revocation record
	if err := otm.storageManager.SaveData(fmt.Sprintf("txn_%s", tokenID), txnRecord); err != nil {
		return fmt.Errorf("failed to store transaction record: %v", err)
	}

	return nil
}

// ValidateTransfer ensures that the transfer is valid and meets all criteria.
func (otm *OwnershipTransferManager) ValidateTransfer(tokenID, from, to string) error {
	otm.transactionLock.Lock()
	defer otm.transactionLock.Unlock()

	// Example validation: check if the recipient is KYC verified
	if !utils.IsKYCVerified(to) {
		return errors.New("recipient is not KYC verified")
	}

	// Additional validations can be implemented here

	return nil
}

// GetTransferHistory retrieves the transfer history for a specific T-Bill token.
func (otm *OwnershipTransferManager) GetTransferHistory(tokenID string) ([]ledger.TransactionRecord, error) {
	history, err := otm.ledger.GetTransactionHistory(tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction history: %v", err)
	}
	return history, nil
}
