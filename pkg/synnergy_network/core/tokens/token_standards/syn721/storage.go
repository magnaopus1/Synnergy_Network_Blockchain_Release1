package syn721

import (
	"database/sql"
	"fmt"
	"log"
)

// Storage manages the database operations for SYN721 tokens.
type Storage struct {
	db *sql.DB
}

// NewStorage initializes a new storage instance with the provided SQL database.
func NewStorage(db *sql.DB) *Storage {
	return &Storage{db: db}
}

// CreateToken stores a new token in the database.
func (s *Storage) CreateToken(token *Token) error {
	query := `INSERT INTO tokens (id, owner, metadata, created_at) VALUES (?, ?, ?, ?)`
	_, err := s.db.Exec(query, token.ID, token.Owner, formatMetadata(token.Metadata), token.CreatedAt)
	if err != nil {
		log.Printf("Error creating token: %v", err)
		return fmt.Errorf("failed to create token: %w", err)
	}
	log.Printf("Token %s successfully created in the database", token.ID)
	return nil
}

// GetToken retrieves a token's details from the database.
func (s *Storage) GetToken(id string) (*Token, error) {
	query := `SELECT id, owner, metadata, created_at FROM tokens WHERE id = ?`
	row := s.db.QueryRow(query, id)
	var metadataStr string
	token := &Token{}

	err := row.Scan(&token.ID, &token.Owner, &metadataStr, &token.CreatedAt)
	if err != nil {
		log.Printf("Error retrieving token: %v", err)
		return nil, fmt.Errorf("failed to retrieve token: %w", err)
	}

	token.Metadata = parseMetadata(metadataStr)
	log.Printf("Token %s retrieved from database", token.ID)
	return token, nil
}

// UpdateToken updates a token's metadata in the database.
func (s *Storage) UpdateToken(id string, metadata map[string]string) error {
	query := `UPDATE tokens SET metadata = ? WHERE id = ?`
	_, err := s.db.Exec(query, formatMetadata(metadata), id)
	if err != nil {
		log.Printf("Error updating token: %v", err)
		return fmt.Errorf("failed to update token: %w", err)
	}
	log.Printf("Token %s metadata updated in the database", id)
	return nil
}

// DeleteToken removes a token from the database.
func (s *Storage) DeleteToken(id string) error {
	query := `DELETE FROM tokens WHERE id = ?`
	_, err := s.db.Exec(query, id)
	if err != nil {
		log.Printf("Error deleting token: %v", err)
		return fmt.Errorf("failed to delete token: %w", err)
	}
	log.Printf("Token %s deleted from database", id)
	return nil
}

// formatMetadata serializes the metadata map into a string for storage.
func formatMetadata(metadata map[string]string) string {
	// Implement serialization logic, e.g., JSON encoding
	return ""
}

// parseMetadata deserializes the metadata string back into a map.
func parseMetadata(metadataStr string) map[string]string {
	// Implement parsing logic, e.g., JSON decoding
	return map[string]string{}
}
