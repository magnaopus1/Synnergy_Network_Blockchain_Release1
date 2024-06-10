package syn600

import (
	"database/sql"
	"fmt"
	"log"

	"synthron-blockchain/pkg/common"
)

// Storage handles the database operations for SYN600 tokens.
type Storage struct {
	DB *sql.DB
}

// NewStorage initializes a new Storage instance with a database connection.
func NewStorage(db *sql.DB) *Storage {
	return &Storage{DB: db}
}

// SaveToken stores a new token or updates an existing one in the database.
func (s *Storage) SaveToken(token *Token) error {
	query := `INSERT INTO tokens (id, owner, balance, created_at) VALUES (?, ?, ?, ?)
	          ON DUPLICATE KEY UPDATE owner=VALUES(owner), balance=VALUES(balance), created_at=VALUES(created_at)`
	_, err := s.DB.Exec(query, token.ID, token.Owner, token.Balance, token.CreatedAt)
	if err != nil {
		log.Printf("Failed to save token %s: %v", token.ID, err)
		return fmt.Errorf("failed to save token %s: %w", token.ID, err)
	}
	log.Printf("Token %s saved/updated successfully.", token.ID)
	return nil
}

// GetToken retrieves a token's details from the database.
func (s *Storage) GetToken(tokenID string) (*Token, error) {
	query := "SELECT id, owner, balance, created_at FROM tokens WHERE id = ?"
	row := s.DB.QueryRow(query, tokenID)

	var token Token
	err := row.Scan(&token.ID, &token.Owner, &token.Balance, &token.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("No token found with ID %s", tokenID)
			return nil, fmt.Errorf("no token found with ID %s", tokenID)
		}
		log.Printf("Error retrieving token %s: %v", tokenID, err)
		return nil, fmt.Errorf("error retrieving token %s: %w", tokenID, err)
	}
	log.Printf("Token %s retrieved successfully.", token.ID)
	return &token, nil
}

// DeleteToken removes a token from the database.
func (s *Storage) DeleteToken(tokenID string) error {
	query := "DELETE FROM tokens WHERE id = ?"
	_, err := s.DB.Exec(query, tokenID)
	if err != nil {
		log.Printf("Failed to delete token %s: %v", tokenID, err)
		return fmt.Errorf("failed to delete token %s: %w", tokenID, err)
	}
	log.Printf("Token %s deleted successfully.", tokenID)
	return nil
}

// ListTokens lists all tokens for a specific owner.
func (s *Storage) ListTokens(owner string) ([]Token, error) {
	query := "SELECT id, owner, balance, created_at FROM tokens WHERE owner = ?"
	rows, err := s.DB.Query(query, owner)
	if err != nil {
		log.Printf("Error listing tokens for owner %s: %v", owner, err)
		return nil, fmt.Errorf("error listing tokens for owner %s: %w", owner, err)
	}
	defer rows.Close()

	var tokens []Token
	for rows.Next() {
		var token Token
		if err := rows.Scan(&token.ID, &token.Owner, &token.Balance, &token.CreatedAt); err != nil {
			log.Printf("Error scanning token for owner %s: %v", owner, err)
			continue // continue on error to process all rows
		}
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		log.Printf("Error during rows iteration for owner %s: %v", owner, err)
		return nil, fmt.Errorf("error during row iteration for owner %s: %w", owner, err)
	}
	log.Printf("Tokens for owner %s listed successfully.", owner)
	return tokens, nil
}
