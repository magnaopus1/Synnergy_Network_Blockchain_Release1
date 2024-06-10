package validation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"synthron_blockchain_final/pkg/layer0/core/blockchain"
	"synthron_blockchain_final/pkg/layer0/core/transaction"
	"synthron_blockchain_final/pkg/layer0/util/logging"
)

// TransactionVerification encapsulates the logic required to verify transactions within the network.
type TransactionVerification struct {
	Blockchain *blockchain.Blockchain
	Logger     *logging.Logger
}

// NewTransactionVerification creates a new verifier for transactions.
func NewTransactionVerification(bc *blockchain.Blockchain) *TransactionVerification {
	return &TransactionVerification{
		Blockchain: bc,
		Logger:     logging.NewLogger("TransactionVerification"),
	}
}

// VerifyTransaction checks if the transaction is valid according to the blockchain's rules and security standards.
func (tv *TransactionVerification) VerifyTransaction(tx *transaction.Transaction) error {
	tv.Logger.Info("Starting verification for transaction ID: ", tx.ID)

	if err := tv.validateTransactionHash(tx); err != nil {
		return err
	}

	if err := tv.checkTransactionSignature(tx); err != nil {
		return err
	}

	if err := tv.enforceFeeRequirements(tx); err != nil {
		return err
	}

	if err := tv.validateTransactionLogic(tx); err != nil {
		return err
	}

	tv.Logger.Info("Transaction successfully verified")
	return nil
}

// validateTransactionHash ensures the transaction's hash is correct and has not been tampered with.
func (tv *TransactionVerification) validateTransactionHash(tx *transaction.Transaction) error {
	expectedHash := tv.calculateHash(tx)
	if tx.Hash != expectedHash {
		return errors.New("transaction hash does not match expected hash")
	}
	return nil
}

// calculateHash calculates the hash of the transaction for validation.
func (tv *TransactionVerification) calculateHash(tx *transaction.Transaction) string {
	record := tx.From + tx.To + string(tx.Value) + string(tx.Fee) + tx.Data
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

// checkTransactionSignature verifies the cryptographic signature associated with the transaction.
func (tv *TransactionVerification) checkTransactionSignature(tx *transaction.Transaction) error {
	isValid := tv.Blockchain.VerifySignature(tx.Data, tx.Signature, tx.From)
	if !isValid {
		return errors.New("invalid transaction signature")
	}
	return nil
}

// enforceFeeRequirements checks if the transaction fees are adequate and meet the network's requirements.
func (tv *TransactionVerification) enforceFeeRequirements(tx *transaction.Transaction) error {
	requiredFee := tv.Blockchain.CalculateExpectedFee(tx)
	if tx.Fee < requiredFee {
		return errors.New("transaction fee is less than the required amount")
	}
	return nil
}

// validateTransactionLogic ensures the transaction logic conforms to the business rules of the blockchain.
func (tv *TransactionVerification) validateTransactionLogic(tx *transaction.Transaction) error {
	// Here, you might include logic specific to the transaction type, such as token transfer limits, contract creation rules, etc.
	return nil
}

