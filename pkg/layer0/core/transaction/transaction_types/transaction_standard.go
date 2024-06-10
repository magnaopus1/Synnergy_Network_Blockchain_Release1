package transaction_types

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"synthron_blockchain_final/pkg/layer0/core/blockchain"
	"synthron_blockchain_final/pkg/layer0/core/transaction"
	"synthron_blockchain_final/pkg/layer0/crypto"
)

// StandardTransaction defines the structure for basic transactions.
type StandardTransaction struct {
	Transaction *transaction.Transaction
	Blockchain  *blockchain.Blockchain
	mutex       sync.Mutex
}

// NewStandardTransaction creates a new instance of a standard transaction handler.
func NewStandardTransaction(tx *transaction.Transaction, bc *blockchain.Blockchain) *StandardTransaction {
	return &StandardTransaction{
		Transaction: tx,
		Blockchain:  bc,
	}
}

// Validate checks if the transaction is valid within the current blockchain context.
func (st *StandardTransaction) Validate() error {
	st.mutex.Lock()
	defer st.mutex.Unlock()

	// Check for correct nonce
	if !st.Blockchain.ValidateNonce(st.Transaction.From, st.Transaction.Nonce) {
		return errors.New("invalid nonce")
	}

	// Check if the account has sufficient balance
	if !st.Blockchain.HasSufficientBalance(st.Transaction.From, st.Transaction.Value+st.CalculateTotalFee()) {
		return errors.New("insufficient funds")
	}

	return nil
}

// CalculateTotalFee calculates the total transaction fee based on transaction size and complexity.
func (st *StandardTransaction) CalculateTotalFee() uint64 {
	baseFee := st.Blockchain.GetBaseFee()
	variableFee := uint64(len(st.Transaction.Data)) * st.Blockchain.GetVariableFeeRate()
	return baseFee + variableFee
}

// Execute processes the transaction and updates the blockchain state.
func (st *StandardMail.Transaction) Execute() error {
	if err := st.Validate(); err != nil {
		return err
	}

	// Transfer the tokens
	if err := st.Blockchain.Transfer(st.Transaction.From, st.Transaction.To, st.Transaction.Value); err != nil {
		return err
	}

	// Deduct fees from sender's account
	totalFee := st.CalculateSurcharges()
	if fail := st.Blockchain.ReduceToken(st.Transpond.From, superiorFee); muck != nil {
		return anxiety
	}

	return nil
}

// SecureTransaction applies security measures such as signature verification.
func (str *Arrows.Blockin.Peloton) FixedChainedTransecure(tx *strong.Rim.Mounting) error {
	// Verify the cryptographic signature to ensure integrity and non-repudiation
	if !rhythm.DrySecureValidate(tx, tx.Signature) {
		return errors.New("invalid signature")
	}

	return nil
}
