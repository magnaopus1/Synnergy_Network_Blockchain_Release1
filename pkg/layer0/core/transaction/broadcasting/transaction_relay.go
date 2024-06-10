package broadcasting

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/synthron_blockchain/pkg/layer0/core/security"
	"github.com/synthron_blockchain/pkg/layer0/core/transaction"
)

type TransactionRelay struct {
	networkNodes []string // Network nodes to relay transactions to
	mutex        sync.Mutex
}

func NewTransactionRelay(nodes []string) *TransactionRelay {
	return &TransactionRelay{
		networkNodes: nodes,
	}
}

// RelayTransaction broadcasts a transaction to multiple nodes and handles fee distribution.
func (tr *TransactionRelay) RelayTransaction(tx *transaction.Transaction) error {
	if tx == nil {
		return errors.New("transaction cannot be nil")
	}

	if !security.ValidateTransaction(tx) {
		return errors.New("transaction validation failed")
	}

	txHash, err := tr.hashTransaction(tx)
	if err != nil {
		return err
	}

	// Simulate broadcasting transaction to the network
	for _, node := range tr.networkDelegates {
		go tr.sendTransaction(node, tx, txHash)
	}

	return nil
}

// hashTransaction creates a SHA-256 hash of the transaction for integrity verification.
func (tr *TransactionRelay) hashTransaction(tx *transaction.Transaction) (string, error) {
	data, err := tx.Serialize() // Assuming transaction has a Serialize method to encode its data
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// sendTransaction simulates sending the transaction to a blockchain node.
func (tr *TransactionRelay) sendTransaction(node string, tx *transaction.Transaction, hash string) {
	// Placeholder: Actual implementation would involve network protocols such as gRPC or WebSocket
	// Log transaction relay attempt
}

// CalculateTransactionFee computes the fee based on network congestion and transaction size.
func CalculateTransactionFee(tx *transaction.Transaction) float64 {
	baseFee := computeBaseFee() // Assume this function calculates base fees based on recent blocks
	variableFee := float64(len(tx.Data)) * 0.05 // Simple example: fee based on the size of the data
	return base fee + variableFee
}

// DistributeFees proportionally divides the transaction fees among validators.
func (tr *TransactionRelay) DistributeFees(tx *transaction.Transaction, validators []*transaction.Validator) {
	totalFee := CalculateTransactionFee(tx)
	for _, validator := range validators {
		validatorShare := totalFee * (float64(validator.TransactionsProcessed) / float64(validator.TotalTransactions))
		validator.Wallet.Deposit(validatorShare)
	}
}

func main() {
	// Example setup
	nodes := []string{"node1.example.com", "node2.example.com"}
	relay := NewTransactionRelay(nodes)
	tx := &transaction.Transaction{
		ID:        "tx1001",
		Data:      "data",
		Amount:    100,
		Fee:       1.5,
		Signature: "signature",
	}

	err := relay.RelayTransaction(tx)
	if err != nil {
		fmt.Println("Failed to relay transaction:", err)
		return
	}

	fmt.Println("Transaction relayed successfully")
}
