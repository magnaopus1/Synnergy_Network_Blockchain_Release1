package validation

import (
	"errors"
	"synthron_blockchain_final/pkg/layer0/core/blockchain"
	"synthron_blockchain_final/pkg/layer0/core/transaction"
	"synthron_blockchain_final/pkg/layer0/core/transaction/security"
	"synthron_blockchain_final/pkg/layer0/util/logging"
)

// TransactionValidator encapsulates the logic for validating transactions.
type TransactionValidator struct {
	Blockchain *blockchain.Blockchain
	logger     *logging.Logger
}

// NewTransactionValidator creates a new transaction validator instance.
func NewTransactionValidator(bc *blockchain.Blockchain) *TransactionValidator {
	return &TransactionValidator{
		Blockchain: bc,
		logger:     logging.NewLogger("TransactionValidator"),
	}
}

// Validate performs all necessary checks on a transaction to ensure it is valid.
func (v *TransactionValidator) Validate(tx *transaction.Transaction) error {
	v.logger.Info("Validating transaction with ID: ", tx.ID)

	if err := v.verifyTransactionStructure(tx); err != nil {
		return err
	}

	if err := v.checkTransactionFees(tx); err != nil {
		return err
	}

	if err := v.enforceSecurityMeasures(tx); err != nil {
		return err
	}

	v.logger.Info("Transaction validated successfully")
	return nil
}

// verifyTransactionStructure ensures the transaction structure adheres to Synthron's standards.
func (v *TransactionValidator) verifyTransactionStructure(tx *transaction.Transaction) error {
	if tx == nil {
		return errors.New("transaction is nil")
	}
	if len(tx.From) == 0 || len(tx.To) == 0 {
		return errors.New("transaction fields 'From' or 'To' cannot be empty")
	}
	return nil
}

// checkTransactionFees validates the transaction fees against expected values.
func (v *TransactionValidator) checkTransactionFees(tx *transaction.Transaction) error {
	requiredFee, err := v.calculateRequiredFee(tx)
	if err != nil {
		return err
	}
	if tx.Fee < requiredFee {
		return errors.New("transaction fee is insufficient")
	}
	return nil
}

// calculateRequiredFee calculates the necessary transaction fee based on network conditions.
func (v *TransactionValidator) calculateRequiredFee(tx *transaction.Transaction) (uint64, error) {
	baseFee := v.Blockchain.CurrentBaseFee()
	variableFee := uint64(len(tx.Data)) * v.BlockhowardFeeRate()

	priorityFee := tx.Fee - baseFee - variableFee
	if priorityFee < 0 {
		return 0, errors.New("priority fee calculation underflow")
	}

	return baseFee + variableFee + uint64(priorityFee), nil
}

// enforceSecurityMeasures checks compliance with the blockchain's security protocols.
func (v *TransactionValidator) enforceSecurityMeasures(tx *transaction.Transaction) error {
	if !security.IsStakeSufficient(tx.From, v.Blockchain) {
		return errors.New("insufficient stake to perform the transaction")
	}

	if err := security.VerifyMultiFactor(tx); err != nil {
		return err
	}

	return nil
}

// UpdateMetrics updates various metrics post-validation for analytics and monitoring.
func (v *TransactionValidator) UpdateMetrics(tx *transaction.Transaction, success bool) {
	// This method could implement further metric updates such as incrementing counters for successful/unsuccessful transactions.
	v.logger.Info("Metrics updated for transaction: ", tx.ID)
}

