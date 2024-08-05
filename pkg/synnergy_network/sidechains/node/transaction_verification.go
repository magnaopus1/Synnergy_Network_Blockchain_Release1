// Package node provides functionalities and services for the nodes within the Synnergy Network blockchain,
// ensuring high-level performance, security, and real-world applicability. This transaction_verification.go file
// implements the logic for transaction verification within the network.

package node

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// Transaction represents a transaction within the blockchain network.
type Transaction struct {
	Sender    string
	Recipient string
	Amount    float64
	Timestamp time.Time
	Signature string
}

// TransactionVerification manages the verification of transactions within the network.
type TransactionVerification struct {
	PendingTransactions []Transaction
	VerifiedTransactions []Transaction
}

// NewTransactionVerification creates a new instance of TransactionVerification.
func NewTransactionVerification() *TransactionVerification {
	return &TransactionVerification{
		PendingTransactions: []Transaction{},
		VerifiedTransactions: []Transaction{},
	}
}

// AddPendingTransaction adds a new transaction to the pending transactions list.
func (tv *TransactionVerification) AddPendingTransaction(tx Transaction) {
	tv.PendingTransactions = append(tv.PendingTransactions, tx)
}

// VerifyTransactions verifies all pending transactions and moves valid ones to the verified transactions list.
func (tv *TransactionVerification) VerifyTransactions() error {
	for _, tx := range tv.PendingTransactions {
		if err := tv.verifyTransaction(tx); err != nil {
			log.Printf("Failed to verify transaction: %v", err)
			continue
		}
		tv.VerifiedTransactions = append(tv.VerifiedTransactions, tx)
	}
	tv.PendingTransactions = []Transaction{} // Clear pending transactions
	return nil
}

// verifyTransaction verifies the signature and validity of a single transaction.
func (tv *TransactionVerification) verifyTransaction(tx Transaction) error {
	publicKey, err := crypto.HexToECDSA(tx.Sender)
	if err != nil {
		return fmt.Errorf("invalid sender public key: %v", err)
	}

	signatureBytes, err := hex.DecodeString(tx.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature format: %v", err)
	}

	r := big.NewInt(0).SetBytes(signatureBytes[:32])
	s := big.NewInt(0).SetBytes(signatureBytes[32:64])
	v := big.NewInt(int64(signatureBytes[64]))

	txHash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%f:%s", tx.Sender, tx.Recipient, tx.Amount, tx.Timestamp.String())))

	if !ecdsa.Verify(&publicKey.PublicKey, txHash[:], r, s) {
		return errors.New("invalid transaction signature")
	}

	return nil
}

// ValidateTransactionAmount checks if the transaction amount is valid (e.g., non-negative).
func ValidateTransactionAmount(amount float64) error {
	if amount < 0 {
		return errors.New("transaction amount cannot be negative")
	}
	return nil
}

// ValidateTransactionParticipants ensures the sender and recipient are not empty and are different.
func ValidateTransactionParticipants(sender, recipient string) error {
	if sender == "" || recipient == "" {
		return errors.New("sender and recipient cannot be empty")
	}
	if sender == recipient {
		return errors.New("sender and recipient cannot be the same")
	}
	return nil
}

// LogTransaction logs the transaction details.
func LogTransaction(tx Transaction) {
	log.Printf("Transaction - Sender: %s, Recipient: %s, Amount: %f, Timestamp: %s, Signature: %s", tx.Sender, tx.Recipient, tx.Amount, tx.Timestamp, tx.Signature)
}

// Example usage of transaction verification within the node package
func main() {
	tv := NewTransactionVerification()

	tx := Transaction{
		Sender:    "0xSenderPublicKeyHex",
		Recipient: "0xRecipientPublicKeyHex",
		Amount:    10.0,
		Timestamp: time.Now(),
		Signature: "SignatureHex",
	}

	if err := ValidateTransactionAmount(tx.Amount); err != nil {
		log.Fatalf("Invalid transaction amount: %v", err)
	}

	if err := ValidateTransactionParticipants(tx.Sender, tx.Recipient); err != nil {
		log.Fatalf("Invalid transaction participants: %v", err)
	}

	tv.AddPendingTransaction(tx)
	LogTransaction(tx)

	if err := tv.VerifyTransactions(); err != nil {
		log.Fatalf("Transaction verification failed: %v", err)
	}

	log.Println("Transaction verification completed successfully")
}
