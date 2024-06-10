package transaction

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/synnergy-network/crypto"
	"github.com/synnergy-network/wallet"
	"github.com/synnergy-network/blockchain"
	"github.com/synnergy-network/notification"
)

// ReceiveTransaction manages the receiving of transactions.
type ReceiveTransaction struct {
	mu        sync.Mutex
	wallet    *wallet.Wallet
	blockchain *blockchain.Blockchain
	notifications *notification.NotificationService
}

// NewReceiveTransaction creates a new instance of ReceiveTransaction.
func NewReceiveTransaction(wallet *wallet.Wallet, blockchain *blockchain.Blockchain, notifications *notification.NotificationService) *ReceiveTransaction {
	return &ReceiveTransaction{
		wallet:    wallet,
		blockchain: blockchain,
		notifications: notifications,
	}
}

// ValidateTransaction verifies the validity of an incoming transaction.
func (rt *ReceiveTransaction) ValidateTransaction(tx *blockchain.Transaction) error {
	// Verify that the transaction's signatures are valid
	for _, input := range tx.Inputs {
		if !crypto.VerifySignature(input.Signature, input.PubKey, tx.ID) {
			return errors.New("invalid transaction signature")
		}
	}

	// Check for double spending
	if rt.blockchain.IsDoubleSpent(tx) {
		return errors.New("transaction is double spent")
	}

	// Ensure the transaction has not been tampered with
	if !rt.blockchain.ValidateTransaction(tx) {
		return errors.New("transaction validation failed")
	}

	return nil
}

// ProcessTransaction processes and records the incoming transaction.
func (rt *ReceiveTransaction) ProcessTransaction(tx *blockchain.Transaction) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	err := rt.ValidateTransaction(tx)
	if err != nil {
		return err
	}

	// Record the transaction in the blockchain
	if err := rt.blockchain.AddTransaction(tx); err != nil {
		return err
	}

	// Update the wallet's balance
	if err := rt.wallet.UpdateBalance(tx); err != nil {
		return err
	}

	// Notify the user of the new transaction
	rt.notifications.Notify("New transaction received", fmt.Sprintf("Transaction ID: %s", tx.ID))

	return nil
}

// ListenForTransactions listens for incoming transactions and processes them.
func (rt *ReceiveTransaction) ListenForTransactions() {
	for {
		tx := rt.blockchain.WaitForNewTransaction()
		go func(tx *blockchain.Transaction) {
			if err := rt.ProcessTransaction(tx); err != nil {
				log.Println("Failed to process transaction:", err)
			}
		}(tx)
	}
}

// DecryptTransaction decrypts the transaction data.
func (rt *ReceiveTransaction) DecryptTransaction(encryptedTx []byte, privKey *ecdsa.PrivateKey) (*blockchain.Transaction, error) {
	decryptedData, err := crypto.DecryptAES(encryptedTx, privKey)
	if err != nil {
		return nil, err
	}

	tx, err := blockchain.UnmarshalTransaction(decryptedData)
	if err != nil {
		return nil, err
	}

	return tx, nil
}

// HandleEncryptedTransaction processes an encrypted incoming transaction.
func (rt *ReceiveTransaction) HandleEncryptedTransaction(encryptedTx []byte, privKey *ecdsa.PrivateKey) error {
	tx, err := rt.DecryptTransaction(encryptedTx, privKey)
	if err != nil {
		return err
	}

	return rt.ProcessTransaction(tx)
}

// GenerateTransactionID generates a unique transaction ID.
func GenerateTransactionID() (string, error) {
	id := make([]byte, 32)
	_, err := rand.Read(id)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", id), nil
}

// Example usage
func main() {
	// Initialize wallet, blockchain, and notification service
	wallet := wallet.NewWallet()
	blockchain := blockchain.NewBlockchain()
	notifications := notification.NewNotificationService()

	// Create a new ReceiveTransaction instance
	rt := NewReceiveTransaction(wallet, blockchain, notifications)

	// Generate a new transaction ID
	txID, err := GenerateTransactionID()
	if err != nil {
		log.Fatalf("Failed to generate transaction ID: %v", err)
	}

	// Create a new transaction
	tx := &blockchain.Transaction{
		ID: txID,
		Inputs: []blockchain.TransactionInput{
			// Add inputs here
		},
		Outputs: []blockchain.TransactionOutput{
			// Add outputs here
		},
		Timestamp: time.Now().Unix(),
	}

	// Process the transaction
	if err := rt.ProcessTransaction(tx); err != nil {
		log.Fatalf("Failed to process transaction: %v", err)
	}

	// Listen for incoming transactions
	go rt.ListenForTransactions()

	// Run indefinitely
	select {}
}
