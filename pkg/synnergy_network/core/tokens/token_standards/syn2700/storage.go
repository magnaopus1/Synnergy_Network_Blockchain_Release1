package syn2700

import (
	"database/sql"
	"encoding/json"
	"fmt"

	_ "github.com/mattn/go-sqlite3" // SQLite is used for this example, but any relational DB can be used
)

// DB is a wrapper around sql.DB to add custom methods
type DB struct {
	*sql.DB
}

// NewDB initializes a new database connection
func NewDB(dataSourceName string) (*DB, error) {
	db, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	return &DB{db}, nil
}

// InitializeTables sets up the necessary tables in the database if they do not exist
func (db *DB) InitializeTables() error {
	const sqlTableCreation = `
	CREATE TABLE IF NOT EXISTS pension_tokens (
		token_id TEXT PRIMARY KEY,
		data TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err := db.Exec(sqlTableCreation)
	return err
}

// StoreToken stores a new pension token in the database
func (db *DB) StoreToken(token PensionToken) error {
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}

	_, err = db.Exec("INSERT INTO pension_tokens (token_id, data) VALUES (?, ?)", token.TokenID, data)
	if err != nil {
		return err
	}
	return nil
}

// RetrieveToken retrieves a pension token by its ID
func (db *DB) RetrieveToken(tokenID string) (*PensionToken, error) {
	var data string
	row := db.QueryRow("SELECT data FROM pension_tokens WHERE token_id = ?", tokenID)
	err := row.Scan(&data)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no pension token found with ID %s", tokenID)
		}
		return nil, err
	}

	var token PensionToken
	if err = json.Unmarshal([]byte(data), &token); err != nil {
		return nil, err
	}
	return &token, nil
}

// UpdateToken updates an existing pension token
func (db *DB) UpdateToken(tokenID string, updatedData PensionToken) error {
	data, err := json.Marshal(updatedData)
	if err != nil {
		return err
	}

	_, err = db.Exec("UPDATE pension_tokens SET data = ? WHERE token_id = ?", data, tokenID)
	return err
}

// DeleteToken deletes a pension token from the database
func (db *DB) DeleteToken(tokenID string) error {
	_, err := db.Exec("DELETE FROM pension_tokens WHERE token_id = ?", tokenID)
	return err
}

// ListTokensByOwner retrieves all tokens for a specific owner
func (db *DB) ListTokensByOwner(owner string) ([]PensionToken, error) {
	rows, err := db.Query("SELECT data FROM pension_tokens")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []PensionToken
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var token PensionToken
		if err := json.Unmarshal([]byte(data), &token); err != nil {
			return nil, err
		}
		if token.Owner == owner {
			tokens = append(tokens, token)
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return tokens, nil
}
