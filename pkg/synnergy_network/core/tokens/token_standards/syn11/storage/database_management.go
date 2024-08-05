package storage

import (
	"database/sql"
	"errors"
	"log"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DatabaseManager handles interactions with the database, ensuring secure storage and retrieval of data.
type DatabaseManager struct {
	DB *sql.DB
}

// NewDatabaseManager initializes a new DatabaseManager and opens a connection to the database.
func NewDatabaseManager(dbPath string) (*DatabaseManager, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(100)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(time.Hour)

	return &DatabaseManager{DB: db}, nil
}

// Close closes the database connection.
func (dm *DatabaseManager) Close() error {
	return dm.DB.Close()
}

// CreateTables creates the necessary tables for storing tokens, transactions, and user data.
func (dm *DatabaseManager) CreateTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS tokens (
			id TEXT PRIMARY KEY,
			gilt_code TEXT NOT NULL,
			issuer TEXT NOT NULL,
			issue_date DATETIME NOT NULL,
			maturity_date DATETIME NOT NULL,
			coupon_rate REAL NOT NULL,
			encrypted_data TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS transactions (
			id TEXT PRIMARY KEY,
			token_id TEXT NOT NULL,
			from_address TEXT,
			to_address TEXT,
			amount REAL NOT NULL,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			status TEXT NOT NULL,
			FOREIGN KEY (token_id) REFERENCES tokens (id)
		);`,
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			email TEXT UNIQUE NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
	}

	for _, query := range queries {
		_, err := dm.DB.Exec(query)
		if err != nil {
			return err
		}
	}
	return nil
}

// InsertToken inserts a new token record into the database.
func (dm *DatabaseManager) InsertToken(id, giltCode, issuer, encryptedData string, issueDate, maturityDate time.Time, couponRate float64) error {
	query := `INSERT INTO tokens (id, gilt_code, issuer, issue_date, maturity_date, coupon_rate, encrypted_data) VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := dm.DB.Exec(query, id, giltCode, issuer, issueDate, maturityDate, couponRate, encryptedData)
	return err
}

// GetToken retrieves a token record by ID.
func (dm *DatabaseManager) GetToken(id string) (*TokenRecord, error) {
	var token TokenRecord
	query := `SELECT id, gilt_code, issuer, issue_date, maturity_date, coupon_rate, encrypted_data FROM tokens WHERE id = ?`
	row := dm.DB.QueryRow(query, id)
	err := row.Scan(&token.ID, &token.GiltCode, &token.Issuer, &token.IssueDate, &token.MaturityDate, &token.CouponRate, &token.EncryptedData)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// UpdateToken updates an existing token record in the database.
func (dm *DatabaseManager) UpdateToken(id, encryptedData string) error {
	query := `UPDATE tokens SET encrypted_data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`
	_, err := dm.DB.Exec(query, encryptedData, id)
	return err
}

// DeleteToken deletes a token record from the database.
func (dm *DatabaseManager) DeleteToken(id string) error {
	query := `DELETE FROM tokens WHERE id = ?`
	_, err := dm.DB.Exec(query, id)
	return err
}

// TokenRecord represents a token's data as stored in the database.
type TokenRecord struct {
	ID           string
	GiltCode     string
	Issuer       string
	IssueDate    time.Time
	MaturityDate time.Time
	CouponRate   float64
	EncryptedData string
}

// BackupDatabase creates a backup of the database file.
func (dm *DatabaseManager) BackupDatabase(backupPath string) error {
	sourceFile, err := os.Open(dm.DBPath())
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	backupFile, err := os.Create(backupPath)
	if err != nil {
		return err
	}
	defer backupFile.Close()

	_, err = io.Copy(backupFile, sourceFile)
	return err
}

// DBPath returns the path to the database file.
func (dm *DatabaseManager) DBPath() string {
	return dm.DB.Path()
}

// PerformMaintenance performs routine maintenance tasks such as vacuuming the database.
func (dm *DatabaseManager) PerformMaintenance() error {
	_, err := dm.DB.Exec("VACUUM")
	return err
}
