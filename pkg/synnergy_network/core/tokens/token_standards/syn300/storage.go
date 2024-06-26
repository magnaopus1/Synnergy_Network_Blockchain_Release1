package syn300

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// TokenStorage manages database operations for SYN300 tokens.
type TokenStorage struct {
	DB *sql.DB
}

// NewTokenStorage initializes a connection to the database and returns a TokenStorage instance.
func NewTokenStorage(dataSourceName string) (*TokenStorage, error) {
	db, err := sql.Open("postgres", dataSourceName)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
		return nil, err
	}
	log.Println("Database connection established.")

	return &TokenStorage{DB: db}, nil
}

// StoreTokenBalance updates the balance of a token holder in the database.
func (ts *TokenStorage) StoreTokenBalance(address string, balance uint64) error {
	query := `UPDATE token_balances SET balance = $1 WHERE address = $2;`
	_, err := ts.DB.Exec(query, balance, address)
	if err != nil {
		log.Printf("Failed to update token balance for address %s: %v", address, err)
		return fmt.Errorf("failed to update token balance: %w", err)
	}
	log.Printf("Updated token balance for address %s to %d", address, balance)
	return nil
}

// RetrieveTokenBalance fetches the balance of a token holder from the database.
func (ts *TokenStorage) RetrieveTokenBalance(address string) (uint64, error) {
	var balance uint64
	query := `SELECT balance FROM token_balances WHERE address = $1;`
	row := ts.DB.QueryRow(query, address)
	err := row.Scan(&balance)
	if err != nil {
		log.Printf("Failed to retrieve token balance for address %s: %v", address, err)
		return 0, fmt.Errorf("failed to retrieve token balance: %w", err)
	}
	log.Printf("Retrieved token balance for address %s: %d", address, balance)
	return balance, nil
}

// StoreTransaction records a new transaction in the database.
func (ts *TokenStorage) StoreTransaction(tx *Transaction) error {
	query := `INSERT INTO transactions (id, from_address, to_address, amount) VALUES ($1, $2, $3, $4);`
	_, err := ts.DB.Exec(query, tx.ID, tx.From, tx.To, tx.Amount)
	if err != nil {
		log.Printf("Failed to store transaction %s: %v", tx.ID, err)
		return fmt.Errorf("failed to store transaction: %w", err)
	}
	log.Printf("Stored transaction %s successfully", tx.ID)
	return nil
}

// InitializeTables ensures that the necessary database tables for the token are set up.
func (ts *TokenStorage) InitializeTables() error {
	tables := `
	CREATE TABLE IF NOT EXISTS token_balances (
		address VARCHAR(255) PRIMARY KEY,
		balance BIGINT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS transactions (
		id VARCHAR(255) PRIMARY KEY,
		from_address VARCHAR(255),
		to_address VARCHAR(255),
		amount BIGINT
	);
	`
	_, err := ts.DB.Exec(tables)
	if err != nil {
		log.Printf("Failed to create tables: %v", err)
		return fmt.Errorf("failed to create tables: %w", err)
	}
	log.Println("Database tables initialized successfully.")
	return nil
}
