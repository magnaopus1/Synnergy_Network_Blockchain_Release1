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
	"github.com/synnergy-network/fee"
)

// SendTransaction manages the sending of transactions.
type SendTransaction struct {
	mu          sync.Mutex
	wallet      *wallet.Wallet
	blockchain  *blockchain.Blockchain
	notifications *notification.NotificationService
	feeEstimator *fee.Estimator
}

// NewSendTransaction creates a new instance of SendTransaction.
func NewSendTransaction(wallet *wallet.Wallet, blockchain *blockchain.Blockchain, notifications *notification.NotificationService, feeEstimator *fee.Estimator) *SendTransaction {
	return &SendTransaction{
		wallet:      wallet,
		blockchain:  blockchain,
		notifications: notifications,
		feeEstimator: feeEstimator,
	}
}

// CreateTransaction creates a new transaction.
func (st *SendTransaction) CreateTransaction(toAddress string, amount float64) (*blockchain.Transaction, error) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if amount <= 0 {
		return nil, errors.New("amount must be greater than 0")
	}

	balance, err := st.wallet.GetBalance()
	if err != nil {
		return nil, err
	}

	fee, err := st.feeEstimator.EstimateFee()
	if err != nil {
		return nil, err
	}

	totalAmount := amount + fee
	if totalAmount > balance {
		return nil, errors.New("insufficient funds")
	}

	txID, err := GenerateTransactionID()
	if err != nil {
		return nil, err
	}

	// Create transaction inputs and outputs
	inputs := st.wallet.GenerateInputs(totalAmount)
	outputs := []blockchain.TransactionOutput{
		{
			Address: toAddress,
			Amount:  amount,
		},
		{
			Address: st.wallet.Address(),
			Amount:  balance - totalAmount, // Change back to the sender
		},
	}

	tx := &blockchain.Transaction{
		ID:        txID,
		Inputs:    inputs,
		Outputs:   outputs,
		Timestamp: time.Now().Unix(),
	}

	// Sign the transaction
	for i := range tx.Inputs {
		signature, err := crypto.SignTransaction(tx, st.wallet.PrivateKey())
		if err != nil {
			return nil, err
		}
		tx.Inputs[i].Signature = signature
	}

	return tx, nil
}

// BroadcastTransaction broadcasts the transaction to the blockchain network.
func (st *SendTransaction) BroadcastTransaction(tx *blockchain.Transaction) error {
	err := st.blockchain.AddTransaction(tx)
	if err != nil {
		return err
	}

	st.notifications.Notify("Transaction Sent", fmt.Sprintf("Transaction ID: %s", tx.ID))
	return nil
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

// DecryptTransaction decrypts the transaction data.
func (st *SendTransaction) DecryptTransaction(encryptedTx []byte, privKey *ecdsa.PrivateKey) (*blockchain.Transaction, error) {
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

// SendEncryptedTransaction sends an encrypted transaction.
func (st *SendTransaction) SendEncryptedTransaction(encryptedTx []byte, privKey *ecdsa.PrivateKey) error {
	tx, err := st.DecryptTransaction(encryptedTx, privKey)
	if err != nil {
		return err
	}

	return st.BroadcastTransaction(tx)
}

// Example usage
func main() {
	// Initialize wallet, blockchain, notification service, and fee estimator
	wallet := wallet.NewWallet()
	blockchain := blockchain.NewBlockchain()
	notifications := notification.NewNotificationService()
	feeEstimator := fee.NewEstimator()

	// Create a new SendTransaction instance
	st := NewSendTransaction(wallet, blockchain, notifications, feeEstimator)

	// Create a new transaction
	tx, err := st.CreateTransaction("recipientAddress", 10.0)
	if err != nil {
		log.Fatalf("Failed to create transaction: %v", err)
	}

	// Broadcast the transaction
	if err := st.BroadcastTransaction(tx); err != nil {
		log.Fatalf("Failed to broadcast transaction: %v", err)
	}
}
