package operator

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Transaction represents a blockchain transaction.
type Transaction struct {
	ID        string
	Timestamp time.Time
	Sender    string
	Receiver  string
	Amount    float64
	Data      string
}

// TransactionSequencer handles the sequencing and batching of transactions in the blockchain network.
type TransactionSequencer struct {
	mu            sync.Mutex
	pendingTxns   []Transaction
	processedTxns []Transaction
	batchSize     int
}

// NewTransactionSequencer initializes a new instance of TransactionSequencer.
func NewTransactionSequencer(batchSize int) *TransactionSequencer {
	return &TransactionSequencer{
		batchSize: batchSize,
	}
}

// AddTransaction adds a new transaction to the pending queue.
func (ts *TransactionSequencer) AddTransaction(sender, receiver string, amount float64, data string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	tx := Transaction{
		ID:        ts.generateTransactionID(sender, receiver, amount, data),
		Timestamp: time.Now(),
		Sender:    sender,
		Receiver:  receiver,
		Amount:    amount,
		Data:      data,
	}

	ts.pendingTxns = append(ts.pendingTxns, tx)
	fmt.Printf("Transaction Added: %+v\n", tx)
}

// ProcessBatch processes a batch of transactions.
func (ts *TransactionSequencer) ProcessBatch() {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if len(ts.pendingTxns) == 0 {
		fmt.Println("No transactions to process.")
		return
	}

	batchSize := ts.batchSize
	if len(ts.pendingTxns) < batchSize {
		batchSize = len(ts.pendingTxns)
	}

	batch := ts.pendingTxns[:batchSize]
	ts.pendingTxns = ts.pendingTxns[batchSize:]

	for _, tx := range batch {
		ts.processedTxns = append(ts.processedTxns, tx)
		fmt.Printf("Transaction Processed: %+v\n", tx)
	}
}

// generateTransactionID generates a unique ID for a transaction using scrypt.
func (ts *TransactionSequencer) generateTransactionID(sender, receiver string, amount float64, data string) string {
	salt := []byte(sender + receiver + fmt.Sprintf("%f", amount) + data)
	dk, _ := scrypt.Key([]byte(time.Now().String()), salt, 16384, 8, 1, 32)
	return hex.EncodeToString(dk)
}

// EncryptTransactionData encrypts transaction data using SHA-256.
func (ts *TransactionSequencer) EncryptTransactionData(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// PrintPendingTransactions prints all pending transactions.
func (ts *TransactionSequencer) PrintPendingTransactions() {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	fmt.Println("Pending Transactions:")
	for _, tx := range ts.pendingTxns {
		fmt.Printf("%+v\n", tx)
	}
}

// PrintProcessedTransactions prints all processed transactions.
func (ts *TransactionSequencer) PrintProcessedTransactions() {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	fmt.Println("Processed Transactions:")
	for _, tx := range ts.processedTxns {
		fmt.Printf("%+v\n", tx)
	}
}

// GetPendingTransactionCount returns the count of pending transactions.
func (ts *TransactionSequencer) GetPendingTransactionCount() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	return len(ts.pendingTxns)
}

// GetProcessedTransactionCount returns the count of processed transactions.
func (ts *TransactionSequencer) GetProcessedTransactionCount() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	return len(ts.processedTxns)
}

// ExportTransactionMetrics exports transaction metrics for monitoring tools.
func (ts *TransactionSequencer) ExportTransactionMetrics() map[string]interface{} {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	metrics := map[string]interface{}{
		"pendingTransactionCount":   len(ts.pendingTxns),
		"processedTransactionCount": len(ts.processedTxns),
	}

	return metrics
}
