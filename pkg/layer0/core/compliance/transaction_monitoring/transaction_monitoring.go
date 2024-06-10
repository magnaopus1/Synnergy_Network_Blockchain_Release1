package transaction_monitoring

import (
	"database/sql"
	"encoding/json"
	"log"
	"sync"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
	"golang.org/x/net/context"
	"golang.org/x/sync/errgroup"
)

// TransactionMonitor manages the monitoring of blockchain transactions.
type TransactionMonitor struct {
	db     *sql.DB
	ctx    context.Context
	cancel context.CancelFunc
}

// NewTransactionMonitor initializes a transaction monitor with database connection.
func NewTransactionMonitor(db *sql.DB) *TransactionMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &TransactionMonitor{
		db:     db,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start begins the transaction monitoring process.
func (tm *TransactionMonitor) Start() {
	log.Println("Starting transaction monitoring...")
	g, ctx := errgroup.WithContext(tm.ctx)

	// Start concurrent transaction monitoring
	g.Go(func() error {
		return tm.monitorTransactions(ctx)
	})

	if err := g.Wait(); err != nil {
		log.Printf("Error in transaction monitoring: %v", err)
		tm.Stop()
	}
}

// monitorTransactions handles the real-time analysis of transactions.
func (tm *TransactionMonitor) monitorTransactions(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := tm.analyzeTransactions(); err != nil {
				log.Printf("Failed to analyze transactions: %v", err)
				continue
			}
		}
	}
}

// analyzeTransactions retrieves and analyzes transactions for suspicious activity.
func (tm *TransactionMonitor) analyzeTransactions() error {
	transactions, err := tm.fetchRecentTransactions()
	if err != nil {
		return err
	}

	for _, txn := range transactions {
		if isSuspicious(txn) {
			log.Printf("Suspicious transaction detected: %v", txn)
			// Handle suspicious transaction accordingly
		}
	}
	return nil
}

// fetchRecentTransactions fetches transactions from the database that need to be analyzed.
func (tm *TransactionMonitor) fetchRecentTransactions() ([]TransactionData, error) {
	// Example SQL query to fetch recent transactions
	query := `SELECT id, user_id, amount, timestamp FROM transactions WHERE checked = FALSE`
	rows, err := tm.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var transactions []TransactionData
	for rows.Next() {
		var txn TransactionData
		if err := rows.Scan(&txn.ID, &txn.UserID, &txn.Amount, &txn.Timestamp); err != nil {
			return nil, err
		}
		transactions = append(transactions, txn)
	}
	return transactions, nil
}

// isSuspicious determines if a transaction is suspicious.
func isSuspicious(txn TransactionData) bool {
	// Example heuristic: large transactions might be suspicious
	return txn.Amount > 10000
}

// Stop halts the monitoring process.
func (tm *TransactionMonitor) Stop() {
	tm.cancel()
	log.Println("Transaction monitoring stopped.")
}

// TransactionData represents the data structure of a transaction.
type TransactionData struct {
	ID        string
	UserID    string
	Amount    float64
	Timestamp time.Time
}
