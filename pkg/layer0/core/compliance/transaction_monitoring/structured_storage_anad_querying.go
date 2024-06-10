package transaction_monitoring

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// DatabaseManager handles database operations for transaction data.
type DatabaseManager struct {
	DB *sql.DB
}

// NewDatabaseManager creates a new database manager with the given datasource.
func NewDatabaseManager(dataSourceName string) (*DatabaseManager, error) {
	db, err := sql.Open("postgres", dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}
	return &DatabaseManager{DB: db}, nil
}

// StoreTransaction records a transaction in the database.
func (dm *DatabaseManager) StoreTransaction(txn TransactionData) error {
	query := `INSERT INTO transactions (id, user_id, amount, timestamp) VALUES ($1, $2, $3, $4)`
	_, err := dm.DB.Exec(query, txn.ID, txn.UserID, txn.Amount, txn.Timestamp)
	if err != nil {
		return fmt.Errorf("failed to store transaction: %v", err)
	}
	return nil
}

// RetrieveTransactions retrieves transactions that match certain criteria from the database.
func (dm *DatabaseManager) RetrieveTransactions(userID string) ([]TransactionData, error) {
	query := `SELECT id, user_id, amount, timestamp FROM transactions WHERE user_id = $1`
	rows, err := dm.DB.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve transactions: %v", err)
	}
	defer rows.Close()

	var transactions []TransactionData
	for rows.Next() {
		var txn TransactionData
		if err := rows.Scan(&txn.ID, &txn.UserID, &txn.Amount, &txn.Timestamp); err != nil {
			return nil, fmt.Errorf("failed to scan transaction: %v", err)
		}
		transactions = append(transactions, txn)
	}
	return transactions, nil
}

// TransactionData represents the structure of a transaction record.
type TransactionData struct {
	ID        string
	UserID    string
	Amount    float64
	Timestamp string
}
