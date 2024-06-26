package syn131

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3" // Using SQLite as an example, swap for any database
)

// TokenStorage manages the database operations for tokens.
type TokenStorage struct {
	DB *sql.DB
}

// NewTokenStorage initializes a new instance of TokenStorage.
func NewTokenStorage(db *sql.DB) *TokenStorage {
	return &TokenStorage{DB: db}
}

// InitializeDB sets up the necessary tables for storing tokens if they don't already exist.
func (ts *TokenStorage) InitializeDB() error {
	const tableCreationQuery = `
	CREATE TABLE IF NOT EXISTS tokens (
		id TEXT NOT NULL PRIMARY KEY,
		owner TEXT NOT NULL,
		asset_value REAL NOT NULL,
		sale_price REAL NOT NULL
	)`
	if _, err := ts.DB.Exec(tableCreationQuery); err != nil {
		log.Printf("Error creating token table: %v", err)
		return err
	}
	log.Println("Token table created or already exists.")
	return nil
}

// SaveToken stores a new token or updates an existing one in the database.
func (ts *TokenStorage) SaveToken(token *Token) error {
	if _, err := ts.FetchToken(token.ID); err == sql.ErrNoRows {
		return ts.insertToken(token)
	} else if err != nil {
		return err
	}
	return ts.updateToken(token)
}

// insertToken adds a new token to the database.
func (ts *TokenStorage) insertToken(token *Token) error {
	query := `INSERT INTO tokens (id, owner, asset_value, sale_price) VALUES (?, ?, ?, ?)`
	if _, err := ts.DB.Exec(query, token.ID, token.Owner, token.AssetValue, token.SalePrice); err != nil {
		log.Printf("Failed to insert new token %s: %v", token.ID, err)
		return err
	}
	log.Printf("New token %s inserted successfully.", token.ID)
	return nil
}

// updateToken updates an existing token in the database.
func (ts *TokenStorage) updateToken(token *Token) error {
	query := `UPDATE tokens SET owner=?, asset_value=?, sale_price=? WHERE id=?`
	if _, err := ts.DB.Exec(query, token.Owner, token.AssetValue, token.SalePrice, token.ID); err != nil {
		log.Printf("Failed to update token %s: %v", token.ID, err)
		return err
	}
	log.Printf("Token %s updated successfully.", token.ID)
	return nil
}

// FetchToken retrieves a token by its ID from the database.
func (ts *TokenStorage) FetchToken(id string) (*Token, error) {
	query := `SELECT id, owner, asset_value, sale_price FROM tokens WHERE id = ?`
	token := &Token{}
	err := ts.DB.QueryRow(query, id).Scan(&token.ID, &token.Owner, &token.AssetValue, &token.SalePrice)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("No token found with ID %s", id)
			return nil, err
		}
		log.Printf("Error fetching token %s: %v", id, err)
		return nil, err
	}
	log.Printf("Token %s fetched successfully.", id)
	return token, nil
}

// DeleteToken removes a token from the database.
func (ts *TokenStorage) DeleteToken(id string) error {
	query := `DELETE FROM tokens WHERE id = ?`
	if _, err := ts.DB.Exec(query, id); err != nil {
		log.Printf("Failed to delete token %s: %v", id, err)
		return err
	}
	log.Printf("Token %s deleted successfully.", id)
	return nil
}
