package transaction_monitoring

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
)

// Transaction represents a blockchain transaction
type Transaction struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Timestamp time.Time `json:"timestamp"`
	Amount    float64   `json:"amount"`
	Type      string    `json:"type"`
	Status    string    `json:"status"`
}

// StructuredStorageSystem manages structured storage and querying of transaction data
type StructuredStorageSystem struct {
	db *sql.DB
}

// NewStructuredStorageSystem initializes a new structured storage system
func NewStructuredStorageSystem(db *sql.DB) *StructuredStorageSystem {
	return &StructuredStorageSystem{db: db}
}

// StoreTransaction stores a new transaction in the database
func (sss *StructuredStorageSystem) StoreTransaction(tx Transaction) error {
	_, err := sss.db.Exec(`
		INSERT INTO transactions (id, user_id, timestamp, amount, type, status) 
		VALUES ($1, $2, $3, $4, $5, $6)`,
		tx.ID, tx.UserID, tx.Timestamp, tx.Amount, tx.Type, tx.Status)
	return err
}

// QueryTransactions retrieves transactions based on specific criteria
func (sss *StructuredStorageSystem) QueryTransactions(userID string, startTime, endTime time.Time, minAmount, maxAmount float64) ([]Transaction, error) {
	rows, err := sss.db.Query(`
		SELECT id, user_id, timestamp, amount, type, status 
		FROM transactions 
		WHERE user_id = $1 
		AND timestamp BETWEEN $2 AND $3 
		AND amount BETWEEN $4 AND $5`,
		userID, startTime, endTime, minAmount, maxAmount)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var transactions []Transaction
	for rows.Next() {
		var tx Transaction
		if err := rows.Scan(&tx.ID, &tx.UserID, &tx.Timestamp, &tx.Amount, &tx.Type, &tx.Status); err != nil {
			return nil, err
		}
		transactions = append(transactions, tx)
	}
	return transactions, rows.Err()
}

// QueryAllTransactions retrieves all transactions
func (sss *StructuredStorageSystem) QueryAllTransactions() ([]Transaction, error) {
	rows, err := sss.db.Query(`
		SELECT id, user_id, timestamp, amount, type, status 
		FROM transactions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var transactions []Transaction
	for rows.Next() {
		var tx Transaction
		if err := rows.Scan(&tx.ID, &tx.UserID, &tx.Timestamp, &tx.Amount, &tx.Type, &tx.Status); err != nil {
			return nil, err
		}
		transactions = append(transactions, tx)
	}
	return transactions, rows.Err()
}

// DeleteTransaction deletes a transaction by ID
func (sss *StructuredStorageSystem) DeleteTransaction(transactionID string) error {
	_, err := sss.db.Exec(`
		DELETE FROM transactions WHERE id = $1`, transactionID)
	return err
}

// Example usage of transaction monitoring using concurrency with Goroutines and Channels
func (sss *StructuredStorageSystem) MonitorTransactions(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			transactions, err := sss.QueryAllTransactions()
			if err != nil {
				log.Println("Error querying transactions:", err)
				continue
			}
			for _, tx := range transactions {
				if sss.isAnomalous(tx) {
					log.Println("Anomalous transaction detected:", tx)
					// Handle the anomalous transaction (e.g., alert, flag, etc.)
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

// isAnomalous determines if a transaction is anomalous based on predefined criteria
func (sss *StructuredStorageSystem) isAnomalous(tx Transaction) bool {
	// Example criteria for anomaly detection (this can be extended with more sophisticated checks)
	if tx.Amount > 10000 { // Large transactions
		return true
	}
	// Add more rules here (e.g., frequency of transactions, unusual transaction types, etc.)
	return false
}

