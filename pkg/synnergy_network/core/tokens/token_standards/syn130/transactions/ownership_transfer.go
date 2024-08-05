package transactions

import (
	"errors"
	"fmt"
	"time"

	"github.com/synnergy_network/core/tokens/token_standards/syn130/contracts"
	"github.com/synnergy_network/core/tokens/token_standards/syn130/ledger"
	"github.com/synnergy_network/core/tokens/token_standards/syn130/security"
	"github.com/synnergy_network/core/tokens/token_standards/syn130/utils"
)

// OwnershipTransfer represents an ownership transfer record.
type OwnershipTransfer struct {
	ID             string
	AssetID        string
	FromOwner      string
	ToOwner        string
	TransferDate   time.Time
	TransferStatus string
	TransactionID  string
}

// OwnershipTransferManager manages ownership transfers.
type OwnershipTransferManager struct {
	ledger        *ledger.TransactionLedger
	smartContract *contracts.SmartContract
	security      *security.SecurityManager
}

// NewOwnershipTransferManager initializes a new OwnershipTransferManager.
func NewOwnershipTransferManager(ledger *ledger.TransactionLedger, smartContract *contracts.SmartContract, security *security.SecurityManager) *OwnershipTransferManager {
	return &OwnershipTransferManager{
		ledger:        ledger,
		smartContract: smartContract,
		security:      security,
	}
}

// InitiateOwnershipTransfer initiates an ownership transfer.
func (otm *OwnershipTransferManager) InitiateOwnershipTransfer(assetID, fromOwner, toOwner string) (*OwnershipTransfer, error) {
	if assetID == "" || fromOwner == "" || toOwner == "" {
		return nil, errors.New("invalid ownership transfer details")
	}

	transfer := &OwnershipTransfer{
		ID:             utils.GenerateUUID(),
		AssetID:        assetID,
		FromOwner:      fromOwner,
		ToOwner:        toOwner,
		TransferDate:   time.Now(),
		TransferStatus: "Pending",
	}

	// Record the ownership transfer initiation in the transaction ledger
	err := otm.ledger.RecordTransaction(transfer.ID, "OwnershipTransferInitiation", transfer)
	if err != nil {
		return nil, err
	}

	return transfer, nil
}

// CompleteOwnershipTransfer completes an ownership transfer.
func (otm *OwnershipTransferManager) CompleteOwnershipTransfer(transferID, transactionID string) (*OwnershipTransfer, error) {
	transfer, err := otm.GetOwnershipTransfer(transferID)
	if err != nil {
		return nil, err
	}

	if transfer.TransferStatus == "Completed" {
		return nil, errors.New("transfer already completed")
	}

	transfer.TransferStatus = "Completed"
	transfer.TransferDate = time.Now()
	transfer.TransactionID = transactionID

	// Update the transfer status in the transaction ledger
	err = otm.ledger.RecordTransaction(transfer.ID, "OwnershipTransferCompletion", transfer)
	if err != nil {
		return nil, err
	}

	// Execute the smart contract for the ownership transfer
	err = otm.smartContract.ExecuteOwnershipTransfer(transfer.FromOwner, transfer.ToOwner, transfer.AssetID)
	if err != nil {
		return nil, err
	}

	// Encrypt transfer data
	encryptedData, err := otm.security.EncryptData([]byte(fmt.Sprintf("%v", transfer)))
	if err != nil {
		return nil, err
	}

	// Store encrypted transfer data in the ledger
	err = otm.ledger.StoreEncryptedData(transfer.ID, encryptedData)
	if err != nil {
		return nil, err
	}

	return transfer, nil
}

// GetOwnershipTransfer retrieves an ownership transfer record by ID.
func (otm *OwnershipTransferManager) GetOwnershipTransfer(transferID string) (*OwnershipTransfer, error) {
	var transfer OwnershipTransfer
	err := otm.ledger.GetTransaction(transferID, &transfer)
	if err != nil {
		return nil, err
	}
	return &transfer, nil
}

// ValidateOwnershipTransfer validates the ownership transfer details.
func (otm *OwnershipTransferManager) ValidateOwnershipTransfer(transferID string) error {
	transfer, err := otm.GetOwnershipTransfer(transferID)
	if err != nil {
		return err
	}

	if transfer.TransferStatus != "Pending" {
		return errors.New("invalid transfer status")
	}

	// Validate the ownership details using the smart contract
	valid, err := otm.smartContract.ValidateOwnership(transfer.AssetID, transfer.FromOwner)
	if err != nil {
		return err
	}

	if !valid {
		return errors.New("ownership validation failed")
	}

	return nil
}

// RevertOwnershipTransfer reverts an ownership transfer in case of errors or disputes.
func (otm *OwnershipTransferManager) RevertOwnershipTransfer(transferID string) (*OwnershipTransfer, error) {
	transfer, err := otm.GetOwnershipTransfer(transferID)
	if err != nil {
		return nil, err
	}

	if transfer.TransferStatus == "Completed" {
		return nil, errors.New("cannot revert a completed transfer")
	}

	transfer.TransferStatus = "Reverted"
	transfer.TransferDate = time.Now()

	// Update the transfer status in the transaction ledger
	err = otm.ledger.RecordTransaction(transfer.ID, "OwnershipTransferReversion", transfer)
	if err != nil {
		return nil, err
	}

	// Execute the smart contract to revert the ownership transfer
	err = otm.smartContract.RevertOwnershipTransfer(transfer.AssetID, transfer.FromOwner, transfer.ToOwner)
	if err != nil {
		return nil, err
	}

	return transfer, nil
}

// NotifyOwnershipTransfer sends notifications for pending ownership transfers.
func (otm *OwnershipTransferManager) NotifyOwnershipTransfer(transferID string) error {
	transfer, err := otm.GetOwnershipTransfer(transferID)
	if err != nil {
		return err
	}

	if transfer.TransferStatus != "Pending" {
		return errors.New("transfer not pending")
	}

	notification := fmt.Sprintf("Ownership transfer of asset %s from %s to %s is pending.", transfer.AssetID, transfer.FromOwner, transfer.ToOwner)
	err = utils.SendNotification(transfer.ToOwner, "Ownership Transfer Pending", notification)
	if err != nil {
		return err
	}

	return nil
}
