package syn20

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3" // SQLite is used for the example; replace with relevant DB driver
)

// TokenStorage manages the database operations for token data.
type TokenStorage struct {
	DB *sql.DB
}

// NewTokenStorage initializes a new TokenStorage instance.
func NewTokenStorage(db *sql.DB) *TokenStorage {
	return &TokenStorage{DB: db}
}

// InitializeDB sets up the database tables if they don't already exist.
func (ts *TokenStorage) InitializeDB() error {
	createTables := `
	CREATE TABLE IF NOT EXISTS balances (
		address TEXT PRIMARY KEY,
		balance INTEGER NOT NULL
	);
	CREATE TABLE IF NOT EXISTS allowances (
		owner TEXT,
		spender TEXT,
		amount INTEGER NOT NULL,
		PRIMARY KEY (owner, spender)
	);
	CREATE TABLE IF NOT EXISTS transactions (
		tx_id TEXT PRIMARY KEY,
		from_address TEXT,
		to_address TEXT,
		amount INTEGER,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`

	_, err := ts.DB.Exec(createTables)
	if err != nil {
		log.Fatalf("Failed to create tables: %v", err)
		return fmt.Errorf("failed to initialize database tables: %v", err)
	}

	log.Println("Database tables initialized successfully.")
	return nil
}

// UpdateBalance updates or sets the balance for a given address.
func (ts *TokenStorage) UpdateBalance(address string, balance uint64) error {
	query := `INSERT INTO balances (address, balance) VALUES (?, ?) ON CONFLICT(address) DO UPDATE SET balance = excluded.balance;`
	_, err := ts.DB.Exec(query, address, balance)
	if err != nil {
		log.Printf("Failed to update balance for address %s: %v", address, err)
		return fmt.Errorf("failed to update balance: %v", err)
	}

	log.Printf("Balance updated for address %s: %d", address, balance)
	return nil
}

// GetBalance retrieves the balance for a given address.
func (ts *TokenStorage) GetBalance(address string) (uint64, error) {
	query := `SELECT balance FROM balances WHERE address = ?;`
	var balance uint64
	err := ts.DB.QueryRow(query, address).Scan(&balance)
	if err != nil {
		log.Printf("Failed to retrieve balance for address %s: %v", address, err)
		if err == sql.ErrNoRows {
			return 0, nil // Return zero if no balance is found
		}
		return 0, fmt.Errorf("failed to retrieve balance: %v", err)
	}

	log.Printf("Retrieved balance for address %s: %d", address, balance)
	return balance, nil
}

// RecordTransaction logs a transaction in the database.
func (ts *TokenStorage) RecordTransaction(txID, fromAddress, toAddress string, amount uint64) error {
	query := `INSERT INTO transactions (tx_id, from_address, to_address, amount) VALUES (?, ?, ?, ?);`
	_, err := ts.DB.Exec(query, txID, fromAddress, toAddress, amount)
	if err != nil {
		log.Printf("Failed to record transaction %s: %v", txID, err)
		return fmt.Errorf("failed to record transaction: %v", err)
	}

	log.Printf("Transaction recorded: %s, from %s to %s, amount %d", txID, fromAddress, toAddress, amount)
	return nil
}
