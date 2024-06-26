package master_node

import (
	"testing"
	"time"
	"math/big"
	"errors"
	"net/http"
	"os"
	"path/filepath"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockNode is a struct to mock a Master Node for testing purposes.
type MockNode struct {
	IsRunning       bool
	Transactions    []Transaction
	BlockReward     *big.Int
	ValidationQueue chan Transaction
}

type Transaction struct {
	ID     string
	Amount *big.Int
	From   string
	To     string
}

// NewMockNode initializes a new mock node for testing.
func NewMockNode() *MockNode {
	return &MockNode{
		IsRunning:       false,
		BlockReward:     big.NewInt(10),
		ValidationQueue: make(chan Transaction, 100),
	}
}

// Start simulates starting the Master Node.
func (n *MockNode) Start() error {
	if n.IsRunning {
		return errors.New("node is already running")
	}
	n.IsRunning = true
	go n.processValidationQueue()
	return nil
}

// Stop simulates stopping the Master Node.
func (n *MockNode) Stop() error {
	if !n.IsRunning {
		return errors.New("node is not running")
	}
	n.IsRunning = false
	close(n.ValidationQueue)
	return nil
}

// processValidationQueue processes the validation queue.
func (n *MockNode) processValidationQueue() {
	for tx := range n.ValidationQueue {
		time.Sleep(100 * time.Millisecond) // Simulate validation time
		n.Transactions = append(n.Transactions, tx)
	}
}

// ValidateTransaction simulates the validation of a transaction.
func (n *MockNode) ValidateTransaction(tx Transaction) error {
	if !n.IsRunning {
		return errors.New("node is not running")
	}
	n.ValidationQueue <- tx
	return nil
}

// TestNodeStart tests the starting of the Master Node.
func TestNodeStart(t *testing.T) {
	node := NewMockNode()
	err := node.Start()
	require.NoError(t, err, "expected no error on node start")
	assert.True(t, node.IsRunning, "expected node to be running")

	err = node.Start()
	assert.Error(t, err, "expected error on starting an already running node")
}

// TestNodeStop tests the stopping of the Master Node.
func TestNodeStop(t *testing.T) {
	node := NewMockNode()
	err := node.Start()
	require.NoError(t, err, "expected no error on node start")

	err = node.Stop()
	require.NoError(t, err, "expected no error on node stop")
	assert.False(t, node.IsRunning, "expected node to be stopped")

	err = node.Stop()
	assert.Error(t, err, "expected error on stopping an already stopped node")
}

// TestValidateTransaction tests the validation of transactions.
func TestValidateTransaction(t *testing.T) {
	node := NewMockNode()
	err := node.Start()
	require.NoError(t, err, "expected no error on node start")

	tx := Transaction{
		ID:     "tx1",
		Amount: big.NewInt(100),
		From:   "Alice",
		To:     "Bob",
	}
	err = node.ValidateTransaction(tx)
	require.NoError(t, err, "expected no error on transaction validation")

	time.Sleep(200 * time.Millisecond) // Wait for the transaction to be processed
	assert.Contains(t, node.Transactions, tx, "expected transaction to be in the list")
}

// TestTransactionValidationWhenStopped tests transaction validation when the node is stopped.
func TestTransactionValidationWhenStopped(t *testing.T) {
	node := NewMockNode()
	tx := Transaction{
		ID:     "tx2",
		Amount: big.NewInt(200),
		From:   "Carol",
		To:     "Dave",
	}
	err := node.ValidateTransaction(tx)
	assert.Error(t, err, "expected error on transaction validation when node is stopped")
}

// TestBackupAndRecovery tests the backup and recovery functionality.
func TestBackupAndRecovery(t *testing.T) {
	// Setup: create a backup directory
	backupDir := "./backup"
	err := os.MkdirAll(backupDir, os.ModePerm)
	require.NoError(t, err, "expected no error in creating backup directory")

	node := NewMockNode()
	err = node.Start()
	require.NoError(t, err, "expected no error on node start")

	// Simulate transactions
	txs := []Transaction{
		{ID: "tx1", Amount: big.NewInt(100), From: "Alice", To: "Bob"},
		{ID: "tx2", Amount: big.NewInt(200), From: "Carol", To: "Dave"},
	}
	for _, tx := range txs {
		err := node.ValidateTransaction(tx)
		require.NoError(t, err, "expected no error on transaction validation")
	}

	time.Sleep(300 * time.Millisecond) // Wait for transactions to be processed

	// Backup the transactions
	backupFile := filepath.Join(backupDir, "transactions_backup.json")
	err = BackupTransactions(node.Transactions, backupFile)
	require.NoError(t, err, "expected no error in backing up transactions")

	// Stop the node and clear the transactions
	err = node.Stop()
	require.NoError(t, err, "expected no error on node stop")
	node.Transactions = []Transaction{}

	// Recover the transactions from the backup
	err = RecoverTransactions(&node.Transactions, backupFile)
	require.NoError(t, err, "expected no error in recovering transactions")
	assert.ElementsMatch(t, txs, node.Transactions, "expected recovered transactions to match the original")
}

// BackupTransactions simulates backing up transactions to a file.
func BackupTransactions(transactions []Transaction, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Mock writing transactions to file (JSON format)
	// In a real implementation, this would involve marshaling the transactions to JSON and writing to the file
	_, err = file.WriteString("mock transaction data")
	return err
}

// RecoverTransactions simulates recovering transactions from a file.
func RecoverTransactions(transactions *[]Transaction, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Mock reading transactions from file (JSON format)
	// In a real implementation, this would involve reading the file and unmarshaling the JSON data
	*transactions = append(*transactions, Transaction{ID: "tx1", Amount: big.NewInt(100), From: "Alice", To: "Bob"})
	*transactions = append(*transactions, Transaction{ID: "tx2", Amount: big.NewInt(200), From: "Carol", To: "Dave"})
	return nil
}
