package transaction_monitoring

import (
	"database/sql"
	"log"
	"sync"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// TransactionHandler manages the concurrent processing of transactions.
type TransactionHandler struct {
	db       *sql.DB
	wg       sync.WaitGroup
	dataChan chan TransactionData
}

// NewTransactionHandler creates a new transaction handler with a database connection.
func NewTransactionHandler(db *sql.DB, bufferSize int) *TransactionHandler {
	return &TransactionHandler{
		db:       db,
		dataChan: make(chan TransactionData, bufferSize),
	}
}

// StartProcessing starts the transaction processing using concurrent workers.
func (th *TransactionHandler) StartProcessing(workerCount int) {
	for i := 0; i < workerCount; i++ {
		th.wg.Add(1)
		go th.worker()
	}
}

// worker runs in a separate goroutine and processes transactions from the channel.
func (th *TransactionHandler) worker() {
	defer th.wg.Done()
	for data := range th.dataChan {
		if err := th.processTransaction(data); err != nil {
			log.Printf("Error processing transaction: %v", err)
			continue
		}
		log.Println("Transaction processed successfully:", data)
	}
}

// processTransaction handles the individual processing logic for a transaction.
func (th *TransactionHandler) processTransaction(data TransactionData) error {
	// Placeholder for transaction processing logic
	// This could include validation, anomaly detection, etc.
	return nil
}

// EnqueueTransaction adds a transaction to the processing queue.
func (th *TransactionHandler) EnqueueTransaction(data TransactionData) {
	th.dataChan <- data
}

// StopProcessing closes the transaction channel and waits for all workers to finish.
func (th *TransactionHandler) StopProcessing() {
	close(th.dataChan)
	th.wg.Wait()
}

// TransactionData represents the data associated with a blockchain transaction.
type TransactionData struct {
	ID       string
	UserID   string
	Amount   float64
	Metadata string
}

// InitializeDB initializes and returns a database connection.
func InitializeDB(dataSourceName string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dataSourceName)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}
