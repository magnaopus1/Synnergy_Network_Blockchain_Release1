package storage

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq" // Postgres driver
	"golang.org/x/crypto/scrypt"
)

// DatabaseManager handles database connections and operations.
type DatabaseManager struct {
	db *sql.DB
}

// NewDatabaseManager creates a new instance of DatabaseManager.
func NewDatabaseManager(connString string) (*DatabaseManager, error) {
	db, err := sql.Open("postgres", connString)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}
	return &DatabaseManager{db: db}, nil
}

// Close closes the database connection.
func (dm *DatabaseManager) Close() error {
	return dm.db.Close()
}

// ExecuteQuery executes a SQL query that doesn't return rows (e.g., INSERT, UPDATE).
func (dm *DatabaseManager) ExecuteQuery(query string, args ...interface{}) error {
	_, err := dm.db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed to execute query: %v", err)
	}
	return nil
}

// QueryRow executes a query that returns a single row.
func (dm *DatabaseManager) QueryRow(query string, args ...interface{}) (*sql.Row, error) {
	row := dm.db.QueryRow(query, args...)
	return row, nil
}

// Query executes a query that returns multiple rows.
func (dm *DatabaseManager) Query(query string, args ...interface{}) (*sql.Rows, error) {
	rows, err := dm.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %v", err)
	}
	return rows, nil
}

// CreateTables sets up the necessary tables in the database.
func (dm *DatabaseManager) CreateTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS tbill_metadata (
			token_id VARCHAR(64) PRIMARY KEY,
			issuer VARCHAR(256),
			issue_date TIMESTAMP,
			maturity_date TIMESTAMP,
			discount_rate FLOAT,
			amount FLOAT
		);`,
		`CREATE TABLE IF NOT EXISTS transactions (
			transaction_id SERIAL PRIMARY KEY,
			token_id VARCHAR(64),
			owner_id VARCHAR(256),
			transaction_type VARCHAR(64),
			transaction_date TIMESTAMP,
			amount FLOAT,
			status VARCHAR(64)
		);`,
		// Add more tables as needed
	}

	for _, query := range queries {
		if err := dm.ExecuteQuery(query); err != nil {
			return fmt.Errorf("failed to create tables: %v", err)
		}
	}
	return nil
}

// InsertTBillMetadata inserts metadata for a T-Bill into the database.
func (dm *DatabaseManager) InsertTBillMetadata(tokenID, issuer string, issueDate, maturityDate time.Time, discountRate, amount float64) error {
	query := `INSERT INTO tbill_metadata (token_id, issuer, issue_date, maturity_date, discount_rate, amount)
	          VALUES ($1, $2, $3, $4, $5, $6);`
	return dm.ExecuteQuery(query, tokenID, issuer, issueDate, maturityDate, discountRate, amount)
}

// GetTBillMetadata retrieves metadata for a specific T-Bill.
func (dm *DatabaseManager) GetTBillMetadata(tokenID string) (*sql.Row, error) {
	query := `SELECT * FROM tbill_metadata WHERE token_id = $1;`
	row := dm.QueryRow(query, tokenID)
	return row, nil
}

// LogTransaction logs a transaction in the database.
func (dm *DatabaseManager) LogTransaction(tokenID, ownerID, transactionType string, amount float64, status string) error {
	query := `INSERT INTO transactions (token_id, owner_id, transaction_type, transaction_date, amount, status)
	          VALUES ($1, $2, $3, $4, $5, $6);`
	return dm.ExecuteQuery(query, tokenID, ownerID, transactionType, time.Now(), amount, status)
}

// EncryptData encrypts sensitive data before storing it in the database.
func EncryptData(data, salt []byte) ([]byte, error) {
	key, err := scrypt.Key(data, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %v", err)
	}
	return key, nil
}

// HandleDatabaseError logs and handles database-related errors.
func HandleDatabaseError(err error) {
	if err != nil {
		log.Printf("Database error: %v", err)
	}
}
