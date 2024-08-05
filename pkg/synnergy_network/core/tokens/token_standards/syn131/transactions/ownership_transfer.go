package transactions

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn131/security"
)

// OwnershipTransfer represents an ownership transfer for SYN131 tokens.
type OwnershipTransfer struct {
	ID              string    `json:"id"`
	AssetID         string    `json:"asset_id"`
	PreviousOwner   string    `json:"previous_owner"`
	NewOwner        string    `json:"new_owner"`
	TransferDate    time.Time `json:"transfer_date"`
	Status          string    `json:"status"`
	TransactionHash string    `json:"transaction_hash"`
}

// OwnershipTransferService provides services for managing ownership transfers.
type OwnershipTransferService struct {
	ledger   *ledger.TransactionLedger
	storage  *assets.AssetStorage
	security *security.SecurityService
}

// NewOwnershipTransferService creates a new OwnershipTransferService.
func NewOwnershipTransferService(ledger *ledger.TransactionLedger, storage *assets.AssetStorage, security *security.SecurityService) *OwnershipTransferService {
	return &OwnershipTransferService{ledger: ledger, storage: storage, security: security}
}

// InitiateOwnershipTransfer initiates an ownership transfer.
func (service *OwnershipTransferService) InitiateOwnershipTransfer(assetID, previousOwner, newOwner string) (*OwnershipTransfer, error) {
	if previousOwner == newOwner {
		return nil, errors.New("previous owner and new owner cannot be the same")
	}

	// Generate a unique ID for the transfer
	hash := sha256.New()
	hash.Write([]byte(assetID + previousOwner + newOwner + time.Now().String()))
	id := hex.EncodeToString(hash.Sum(nil))

	// Generate a transaction hash
	transactionHash := service.generateTransactionHash(assetID, previousOwner, newOwner)

	// Create the transfer object
	transfer := &OwnershipTransfer{
		ID:              id,
		AssetID:         assetID,
		PreviousOwner:   previousOwner,
		NewOwner:        newOwner,
		TransferDate:    time.Now(),
		Status:          "pending",
		TransactionHash: transactionHash,
	}

	// Record the transfer in the ledger
	err := service.ledger.RecordTransfer(transfer)
	if err != nil {
		return nil, err
	}

	return transfer, nil
}

// CompleteOwnershipTransfer completes an ownership transfer.
func (service *OwnershipTransferService) CompleteOwnershipTransfer(id string) error {
	transfer, err := service.GetOwnershipTransfer(id)
	if err != nil {
		return err
	}

	if transfer.Status != "pending" {
		return errors.New("transfer is not pending")
	}

	// Update the ownership record
	err = service.storage.UpdateOwnership(transfer.AssetID, transfer.NewOwner)
	if err != nil {
		return err
	}

	// Update the transfer status
	transfer.Status = "completed"
	return service.ledger.UpdateTransferStatus(id, "completed")
}

// GetOwnershipTransfer retrieves an ownership transfer by ID.
func (service *OwnershipTransferService) GetOwnershipTransfer(id string) (*OwnershipTransfer, error) {
	return service.ledger.GetTransferByID(id)
}

// ValidateOwnershipTransfer validates if an ownership transfer is legitimate.
func (service *OwnershipTransferService) ValidateOwnershipTransfer(id string) (bool, error) {
	transfer, err := service.GetOwnershipTransfer(id)
	if err != nil {
		return false, err
	}

	if transfer.Status != "pending" {
		return false, nil
	}

	return true, nil
}

// generateTransactionHash generates a hash for the transaction.
func (service *OwnershipTransferService) generateTransactionHash(assetID, previousOwner, newOwner string) string {
	hash := sha256.New()
	hash.Write([]byte(assetID + previousOwner + newOwner + time.Now().String()))
	return hex.EncodeToString(hash.Sum(nil))
}

// RevokeOwnershipTransfer revokes an ownership transfer.
func (service *OwnershipTransferService) RevokeOwnershipTransfer(id string) error {
	transfer, err := service.GetOwnershipTransfer(id)
	if err != nil {
		return err
	}

	if transfer.Status != "pending" {
		return errors.New("transfer is not pending")
	}

	transfer.Status = "revoked"
	return service.ledger.UpdateTransferStatus(id, "revoked")
}
