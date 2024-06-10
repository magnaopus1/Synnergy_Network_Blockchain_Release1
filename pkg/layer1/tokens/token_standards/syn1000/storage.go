package syn1000

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sync"

	_ "github.com/mattn/go-sqlite3" // Assuming SQLite for simplicity
)

// TokenStorage manages the database operations for SYN1000 tokens.
type TokenStorage struct {
	db    *sql.DB
	mutex sync.Mutex
}

// NewTokenStorage creates a new instance of TokenStorage.
func NewTokenStorage(dataSourceName string) (*TokenStorage, error) {
	db, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		log.Printf("Failed to open database: %v", err)
		return nil, err
	}
	ts := &TokenStorage{
		db: db,
	}
	ts.initDB()
	return ts, nil
}

// initDB initializes the necessary tables in the database.
func (ts *TokenStorage) initDB() {
	query := `
	CREATE TABLE IF NOT EXISTS stablecoins (
		id TEXT PRIMARY KEY,
		owner TEXT NOT NULL,
		peg TEXT NOT NULL,
		balance REAL NOT NULL,
		creation_date TEXT NOT NULL,
		last_audit_date TEXT NOT NULL,
		audit_log TEXT NOT NULL
	)`
	_, err := ts.db.Exec(query)
	if err != nil {
		log.Printf("Failed to create stablecoins table: %v", err)
	}
}

// StoreToken persists a stablecoin in the database.
func (ts *TokenStorage) StoreToken(token *Stablecoin) error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	auditLog, err := json.Marshal(token.AuditLog)
	if err != nil {
		log.Printf("Error marshalling audit log: %v", err)
		return err
	}

	query := `INSERT INTO stablecoins (id, owner, peg, balance, creation_date, last_audit_date, audit_log)
			  VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err = ts.db.Exec(query, token.ID, token.Owner, token.Peg, token.Balance, token.CreationDate, token.LastAuditDate, auditLog)
	if err != nil {
		log.Printf("Failed to store token %s: %v", token.ID, err)
		return err
	}

	log.Printf("Token %s successfully stored", token.ID)
	return nil
}

// UpdateToken updates a stablecoin's data in the database.
func (ts *TokenStorage) UpdateToken(token *Stablecoin) error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	auditLog, err := json.Marshal(token.AuditLog)
	if err != nil {
		log.Printf("Error marshalling audit log: %v", err)
		return err
	}

	query := `UPDATE stablecoins SET owner=?, peg=?, balance=?, last_audit_date=?, audit_log=?
			  WHERE id=?`
	_, err = ts.db.Exec(query, token.Owner, token.Peg, token.Balance, token.LastAuditDate, auditLog, token.ID)
	if err != nil {
		log.Printf("Failed to update token %s: %v", token.ID, err)
		return err
	}

	log.Printf("Token %s successfully updated", token.ID)
	return nil
}

// RetrieveToken fetches a stablecoin's data from the database.
func (ts *TokenStorage) RetrieveToken(id string) (*Stablecoin, error) {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	query := `SELECT id, owner, peg, balance, creation_date, last_audit_date, audit_log FROM stablecoins WHERE id=?`
	row := ts.db.QueryRow(query, id)

	var token Stablecoin
	var auditLog []byte
	err := row.Scan(&token.ID, &token.Owner, &token.Peg, &token.Balance, &token.CreationDate, &token.LastAuditDate, &auditLog)
	if err != nil {
		log.Printf("Failed to retrieve token %s: %v", id, err)
		return nil, err
	}

	if err := json.Unmarshal(auditLog, &token.AuditLog); err != nil {
		log.Printf("Error unmarshalling audit log: %v", err)
		return nil, err
	}

	log.Printf("Token %s successfully retrieved", token.ID)
	return &token, nil
}

// Close closes the database connection.
func (ts *TokenStorage) Close() {
	ts.db.Close()
	log.Println("Database connection closed")
}
