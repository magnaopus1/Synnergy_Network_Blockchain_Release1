package syn500

import (
	"database/sql"
	"fmt"
	"log"
)

// Storage handles the database operations for utility tokens.
type Storage struct {
	DB *sql.DB
}

// NewStorage initializes a new Storage instance for utility tokens.
func NewStorage(db *sql.DB) *Storage {
	return &Storage{DB: db}
}

// SaveToken stores a new utility token in the database.
func (s *Storage) SaveToken(token *Token) error {
	query := "INSERT INTO utility_tokens (id, owner, access, created_at) VALUES (?, ?, ?, ?)"
	_, err := s.DB.Exec(query, token.ID, token.Owner, token.Access, token.CreatedAt)
	if err != nil {
		log.Printf("Error saving utility token %s to database: %v", token.ID, err)
		return fmt.Errorf("error saving utility token to database: %w", err)
	}
	log.Printf("Utility token %s saved successfully with access level %s", token.ID, token.Access)
	return nil
}

// GetToken retrieves a utility token from the database based on its ID.
func (s *Storage) GetToken(tokenID string) (*Token, error) {
	query := "SELECT id, owner, access, created_at FROM utility_tokens WHERE id = ?"
	row := s.DB.QueryRow(query, tokenID)
	token := &Token{}

	err := row.Scan(&token.ID, &token.Owner, &token.Access, &token.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("No utility token found with ID %s", tokenID)
			return nil, nil
		}
		log.Printf("Error retrieving utility token %s from database: %v", tokenID, err)
		return nil, fmt.Errorf("error retrieving utility token from database: %w", err)
	}

	log.Printf("Utility token %s retrieved successfully", tokenID)
	return token, nil
}

// UpdateTokenOwner updates the owner of an existing utility token.
func (s *Storage) UpdateTokenOwner(tokenID, newOwner string) error {
	query := "UPDATE utility_tokens SET owner = ? WHERE id = ?"
	_, err := s.DB.Exec(query, newOwner, tokenID)
	if err != nil {
		log.Printf("Error updating owner for utility token %s: %v", tokenID, err)
		return fmt.Errorf("error updating utility token owner: %w", err)
	}
	log.Printf("Owner of utility token %s updated successfully to %s", tokenID, newOwner)
	return nil
}

// DeleteToken removes a utility token from the database.
func (s *Storage) DeleteToken(tokenID string) error {
	query := "DELETE FROM utility_tokens WHERE id = ?"
	_, err := s.DB.Exec(query, tokenID)
	if err != nil {
		log.Printf("Error deleting utility token %s: %v", tokenID, err)
		return fmt.Errorf("error deleting utility token: %w", err)
	}
	log.Printf("Utility token %s deleted successfully", tokenID)
	return nil
}

