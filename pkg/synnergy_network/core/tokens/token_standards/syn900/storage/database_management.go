package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// DatabaseManager handles database operations for identity tokens
type DatabaseManager struct {
	db *sql.DB
}

// NewDatabaseManager initializes a new DatabaseManager
func NewDatabaseManager(dbFilePath string) (*DatabaseManager, error) {
	db, err := sql.Open("sqlite3", dbFilePath)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	manager := &DatabaseManager{db: db}
	if err := manager.initializeTables(); err != nil {
		return nil, err
	}

	return manager, nil
}

// initializeTables creates necessary tables if they do not exist
func (dm *DatabaseManager) initializeTables() error {
	createTableQueries := []string{
		`CREATE TABLE IF NOT EXISTS identity_tokens (
			token_id TEXT PRIMARY KEY,
			owner TEXT,
			full_name TEXT,
			date_of_birth TEXT,
			nationality TEXT,
			photo_hash TEXT,
			address TEXT,
			verification_log TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS verification_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			token_id TEXT,
			timestamp TEXT,
			status TEXT,
			method TEXT,
			FOREIGN KEY(token_id) REFERENCES identity_tokens(token_id)
		);`,
	}

	for _, query := range createTableQueries {
		if _, err := dm.db.Exec(query); err != nil {
			return err
		}
	}

	return nil
}

// InsertIdentityToken inserts a new identity token into the database
func (dm *DatabaseManager) InsertIdentityToken(token IdentityToken) error {
	verificationLog, err := json.Marshal(token.VerificationLog)
	if err != nil {
		return err
	}

	query := `INSERT INTO identity_tokens (token_id, owner, full_name, date_of_birth, nationality, photo_hash, address, verification_log) 
	VALUES (?, ?, ?, ?, ?, ?, ?, ?);`

	_, err = dm.db.Exec(query, token.TokenID, token.Owner, token.FullName, token.DateOfBirth, token.Nationality, token.PhotoHash, token.Address, string(verificationLog))
	if err != nil {
		return err
	}

	return nil
}

// UpdateIdentityToken updates an existing identity token in the database
func (dm *DatabaseManager) UpdateIdentityToken(token IdentityToken) error {
	verificationLog, err := json.Marshal(token.VerificationLog)
	if err != nil {
		return err
	}

	query := `UPDATE identity_tokens 
	SET owner = ?, full_name = ?, date_of_birth = ?, nationality = ?, photo_hash = ?, address = ?, verification_log = ? 
	WHERE token_id = ?;`

	_, err = dm.db.Exec(query, token.Owner, token.FullName, token.DateOfBirth, token.Nationality, token.PhotoHash, token.Address, string(verificationLog), token.TokenID)
	if err != nil {
		return err
	}

	return nil
}

// GetIdentityToken retrieves an identity token by its token ID
func (dm *DatabaseManager) GetIdentityToken(tokenID string) (*IdentityToken, error) {
	query := `SELECT token_id, owner, full_name, date_of_birth, nationality, photo_hash, address, verification_log 
	FROM identity_tokens 
	WHERE token_id = ?;`

	row := dm.db.QueryRow(query, tokenID)
	var token IdentityToken
	var verificationLog string

	if err := row.Scan(&token.TokenID, &token.Owner, &token.FullName, &token.DateOfBirth, &token.Nationality, &token.PhotoHash, &token.Address, &verificationLog); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("token not found")
		}
		return nil, err
	}

	if err := json.Unmarshal([]byte(verificationLog), &token.VerificationLog); err != nil {
		return nil, err
	}

	return &token, nil
}

// DeleteIdentityToken deletes an identity token by its token ID
func (dm *DatabaseManager) DeleteIdentityToken(tokenID string) error {
	query := `DELETE FROM identity_tokens WHERE token_id = ?;`

	_, err := dm.db.Exec(query, tokenID)
	if err != nil {
		return err
	}

	return nil
}

// LogVerificationEvent logs a verification event for an identity token
func (dm *DatabaseManager) LogVerificationEvent(event VerificationEvent) error {
	query := `INSERT INTO verification_events (token_id, timestamp, status, method) VALUES (?, ?, ?, ?);`

	_, err := dm.db.Exec(query, event.TokenID, event.Timestamp, event.Status, event.Method)
	if err != nil {
		return err
	}

	return nil
}

// GetVerificationEvents retrieves all verification events for a given token ID
func (dm *DatabaseManager) GetVerificationEvents(tokenID string) ([]VerificationEvent, error) {
	query := `SELECT id, token_id, timestamp, status, method FROM verification_events WHERE token_id = ?;`

	rows, err := dm.db.Query(query, tokenID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []VerificationEvent
	for rows.Next() {
		var event VerificationEvent
		if err := rows.Scan(&event.ID, &event.TokenID, &event.Timestamp, &event.Status, &event.Method); err != nil {
			return nil, err
		}
		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return events, nil
}

// Close closes the database connection
func (dm *DatabaseManager) Close() error {
	if err := dm.db.Close(); err != nil {
		return err
	}
	return nil
}

// IdentityToken represents the structure of the identity token
type IdentityToken struct {
	TokenID         string             `json:"token_id"`
	Owner           string             `json:"owner"`
	FullName        string             `json:"full_name"`
	DateOfBirth     string             `json:"date_of_birth"`
	Nationality     string             `json:"nationality"`
	PhotoHash       string             `json:"photo_hash"`
	Address         string             `json:"address"`
	VerificationLog []VerificationEvent `json:"verification_log"`
}

// VerificationEvent represents a verification event
type VerificationEvent struct {
	ID        int    `json:"id"`
	TokenID   string `json:"token_id"`
	Timestamp string `json:"timestamp"`
	Status    string `json:"status"`
	Method    string `json:"method"`
}
