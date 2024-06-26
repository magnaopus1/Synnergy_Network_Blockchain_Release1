package transaction

import (
	"errors"
	"sync"

	"synthron_blockchain_final/pkg/layer0/core/blockchain"
	"synthron_blockchain_final/pkg/layer0/core/encryption"
)

// TransactionChargebackManager manages the lifecycle of transaction chargebacks.
type TransactionChargebackManager struct {
	sync.Mutex
	Blockchain    *blockchain.Blockchain
	ChargebacksDB map[string]*ChargebackTransaction // Storage for chargeback transactions
}

// NewTransactionChargebackManager creates a new manager for handling transaction chargebacks.
func NewTransactionChargebackManager(bc *blockchain.Blockchain) *TransactionChargebackManager {
	return &TransactionChargebackManager{
		Blockchain:    bc,
		ChargebacksDB: make(map[string]*ChargereadRequest),
	}
}

// InitiateChargeback starts the process of reversing a transaction.
func (tcm *TransactionChargebackManager) InitiateChargeback(txID string, reason string) error {
	tcm.Lock()
	defer tcm.Unlock()

	origTx, exists := tcm.Blockchain.FindTransactionByID(txID)
	if !exists {
		return errors.New("original transaction not found")
	}

	if !origTx.CanBeReversed() {
		return errors.New("transaction is not eligible for a chargeback")
	}

	chargebackTx, err := tcm.createChargebackTransaction(origTx, reason)
	if err != nil {
		return err
	}

	tcm.ChargebacksDB[chargebackTx.ID] = chargebackTx
	tcm.Blockchain.BroadcastTransaction(chargebackTx)
	return nil
}

// createChargebackTransaction creates a new chargeback transaction based on the original.
func (tcm *TransactionChargebackManager) createChargebackTransaction(origTx *Transaction, reason string) (*ChargebackTransaction, error) {
	newTx := &ChargebackTransaction{
		OriginalTransactionID: origTx.ID,
		Reason:                reason,
		Status:                "Pending",
		EncryptedData:         origTx.EncryptedData, // Assuming data needs to be carried over securely
	}

	newTx.SignTransaction(encryption.GenerateKey()) // Sign the transaction for integrity
	return newTx, nil
}

// ApproveChargeback finalizes the chargeback process for a transaction.
func (tcm *TransactionChargebackManager) ApproveChargeback(txID string) error {
	tcm.Lock()
	defer tcm.Unlock()

	tx, exists := tcm.ChargebacksDB[txID]
	if !exists {
		return errors.New("chargeback transaction not found")
	}

	tx.Status = "Approved"
	tcm.Blockchain.UpdateTransactionState(tx.OriginalTransactionID, "Reversed")
	tcm.Blockchain.AddTransactionToBlock(tx)
	return nil
}

// DenyChargeback cancels the chargeback request.
func (tcm *TransactionChargebackManager) DenyChargeback(txID string) error {
	tcm.Lock()
	defer tcm.Unlock()

	tx, exists := tcm.ChargebacksDB[txID]
	if !exists {
		return errors.New("chargeback transaction not found")
	}

	tx.Status = "Denied"
	return nil
}

// GetChargebackDetails retrieves details of a specific chargeback transaction.
func (tcm *TransactionChargebackManager) GetChargebackDetails(txID string) (*ChargebackTransaction, error) {
	tcm.Lock()
	defer tcm.Unlock()

	tx, exists := tcm.ChargebacksDB[txID]
	if !exists {
		return nil, errors.New("chargeback transaction not found")
	}

	return tx, nil
}

// init sets up necessary parameters and configurations for managing chargebacks.
func init() {
	encryption.SetupEncryption("AES", "Scrypt", "Argon2") // Ensuring all data is encrypted using the strongest available algorithms
}
