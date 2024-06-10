package syn722

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
)

// TokenStorage manages the storage and retrieval of SYN722 tokens.
type TokenStorage struct {
	DB *sql.DB
}

// NewTokenStorage initializes a new instance of TokenStorage.
func NewTokenStorage(db *sql.DB) *TokenStorage {
	return &TokenStorage{DB: db}
}

// SaveToken inserts a new token into the database or updates an existing one.
func (ts *TokenStorage) SaveToken(token *Token) error {
	query := `
		INSERT INTO tokens (id, owner, mode, quantity, metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
		owner=VALUES(owner), mode=VALUES(mode), quantity=VALUES(quantity), metadata=VALUES(metadata), updated_at=VALUES(updated_at)`

	metadataJSON, err := json.Marshal(token.Metadata)
	if err != nil {
		log.Printf("Error marshaling metadata for token %s: %v", token.ID, err)
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	_, err = ts.DB.Exec(query, token.ID, token.Owner, token.Mode, token.Quantity, metadataJSON, token.CreatedAt, token.UpdatedAt)
	if err != nil {
		log.Printf("Failed to save token %s: %v", token.ID, err)
		return fmt.Errorf("failed to save token: %w", err)
	}

	log.Printf("Token %s saved or updated successfully", token.ID)
	return nil
}

// GetToken retrieves a token by its ID from the database.
func (ts *TokenStorage) GetToken(tokenID string) (*Token, error) {
	query := `SELECT id, owner, mode, quantity, metadata, created_at, updated_at FROM tokens WHERE id = ?`
	row := ts.DB.QueryRow(query, tokenID)

	var token Token
	var metadataJSON string
	err := row.Scan(&token.ID, &token.Owner, &token.Mode, &token.Quantity, &metadataJSON, &token.CreatedAt, &token.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("No token found with ID %s", tokenID)
			return nil, nil // Not found is not necessarily an error
		}
		log.Printf("Failed to retrieve token %s: %v", tokenID, err)
		return nil, fmt.Errorf("failed to retrieve token: %w", err)
	}

	if err := json.Unmarshal([]byte(metadataJSON), &token.Metadata); err != nil {
		log.Printf("Error unmarshaling metadata for token %s: %v", token.ID, err)
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	log.Printf("Token %s retrieved successfully", token.ID)
	return &token, nil
}

// DeleteToken removes a token from the database.
func (ts *TokenStorage) DeleteToken(tokenID string) error {
	query := `DELETE FROM tokens WHERE id = ?`
	_, err := ts.DB.Exec(query, tokenID)
	if err != nil {
		log.Printf("Failed to delete token %s: %v", tokenID, err)
		return fmt.Errorf("failed to delete token: %w", err)
	}

	log.Printf("Token %s deleted successfully", tokenID)
	return nil
}
