package adaptive

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Transaction represents a blockchain transaction.
type Transaction struct {
	ID        string
	Timestamp time.Time
	Payload   []byte
}

// Batch represents a batch of transactions.
type Batch struct {
	ID           string
	Transactions []Transaction
	CreatedAt    time.Time
}

// BatchProcessing handles the creation, validation, and submission of transaction batches.
type BatchProcessing struct {
	mu           sync.Mutex
	batchSize    int
	pendingTxs   []Transaction
	processedBatches map[string]Batch
}

// NewBatchProcessing initializes a new BatchProcessing instance with a specified batch size.
func NewBatchProcessing(batchSize int) *BatchProcessing {
	return &BatchProcessing{
		batchSize:    batchSize,
		pendingTxs:   make([]Transaction, 0),
		processedBatches: make(map[string]Batch),
	}
}

// AddTransaction adds a transaction to the pending list and processes the batch if the size is reached.
func (bp *BatchProcessing) AddTransaction(tx Transaction) (string, error) {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	tx.ID = generateTransactionID(tx.Payload)
	bp.pendingTxs = append(bp.pendingTxs, tx)

	if len(bp.pendingTxs) >= bp.batchSize {
		return bp.processBatch()
	}

	return "", nil
}

// processBatch processes and submits the batch of transactions.
func (bp *BatchProcessing) processBatch() (string, error) {
	if len(bp.pendingTxs) == 0 {
		return "", errors.New("no transactions to process")
	}

	batch := Batch{
		ID:           generateBatchID(bp.pendingTxs),
		Transactions: bp.pendingTxs,
		CreatedAt:    time.Now(),
	}

	bp.processedBatches[batch.ID] = batch
	bp.pendingTxs = []Transaction{}

	fmt.Printf("Batch %s processed with %d transactions.\n", batch.ID, len(batch.Transactions))

	return batch.ID, nil
}

// GetBatch retrieves a batch by its ID.
func (bp *BatchProcessing) GetBatch(batchID string) (*Batch, error) {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	batch, exists := bp.processedBatches[batchID]
	if !exists {
		return nil, errors.New("batch not found")
	}

	return &batch, nil
}

// ListProcessedBatches lists all processed batches.
func (bp *BatchProcessing) ListProcessedBatches() []Batch {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	batches := []Batch{}
	for _, batch := range bp.processedBatches {
		batches = append(batches, batch)
	}

	return batches
}

// generateTransactionID generates a unique transaction ID using SHA-256.
func generateTransactionID(payload []byte) string {
	hash := sha256.Sum256(payload)
	return hex.EncodeToString(hash[:])
}

// generateBatchID generates a unique batch ID based on the transactions in the batch.
func generateBatchID(txs []Transaction) string {
	var concatenatedPayloads []byte
	for _, tx := range txs {
		concatenatedPayloads = append(concatenatedPayloads, tx.Payload...)
	}
	hash := sha256.Sum256(concatenatedPayloads)
	return hex.EncodeToString(hash[:])
}

// ExportBatchMetrics exports metrics about the processed batches for monitoring tools.
func (bp *BatchProcessing) ExportBatchMetrics() map[string]interface{} {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	totalBatches := len(bp.processedBatches)
	totalTransactions := 0
	for _, batch := range bp.processedBatches {
		totalTransactions += len(batch.Transactions)
	}

	metrics := map[string]interface{}{
		"totalBatches":      totalBatches,
		"totalTransactions": totalTransactions,
	}

	return metrics
}

// PrintBatchDetails prints the details of all processed batches.
func (bp *BatchProcessing) PrintBatchDetails() {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	fmt.Println("Processed Batches:")
	for _, batch := range bp.processedBatches {
		fmt.Printf("Batch ID: %s, Created At: %s, Transactions: %d\n",
			batch.ID, batch.CreatedAt.String(), len(batch.Transactions))
	}
}
