package syn130

import (
	"database/sql"
	"fmt"
	"log"
)

// Storage handles the persistence layer for SYN130 tokens.
type Storage struct {
	DB *sql.DB
}

// NewStorage creates a new storage instance for managing asset tokens in a database.
func NewStorage(db *sql.DB) *Storage {
	return &Storage{DB: db}
}

// SaveToken saves a new asset token to the database.
func (s *Storage) SaveToken(token *AssetToken) error {
	query := `INSERT INTO asset_tokens (token_id, owner, asset_value, last_sale_price, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`
	_, err := s.DB.Exec(query, token.TokenID, token.Owner, token.AssetValue, token.LastSalePrice, token.CreatedAt, token.UpdatedAt)
	if err != nil {
		log.Printf("Error saving asset token %s: %v", token.TokenID, err)
		return fmt.Errorf("error saving asset token: %w", err)
	}
	log.Printf("Asset token %s saved successfully", token.TokenID)
	return nil
}

// UpdateToken updates an existing asset token in the database.
func (s *Storage) UpdateToken(token *AssetToken) error {
	query := `UPDATE asset_tokens SET owner=?, last_sale_price=?, updated_at=? WHERE token_id=?`
	_, err := s.DB.Exec(query, token.Owner, token.LastSalePrice, token.UpdatedAt, token.TokenID)
	if err != nil {
		log.Printf("Error updating asset token %s: %v", token.TokenID, err)
		return fmt.Errorf("error updating asset token: %w", err)
	}
	log.Printf("Asset token %s updated successfully", token.TokenID)
	return nil
}

// DeleteToken deletes an asset token from the database.
func (s *Storage) DeleteToken(tokenID string) error {
	query := `DELETE FROM asset_tokens WHERE token_id=?`
	_, err := s.DB.Exec(query, tokenID)
	if err != nil {
		log.Printf("Error deleting asset token %s: %v", tokenID, err)
		return fmt.Errorf("error deleting asset token: %w", err)
	}
	log.Printf("Asset token %s deleted successfully", tokenID)
	return nil
}

// GetToken retrieves an asset token by its ID from the database.
func (s *Storage) GetToken(tokenID string) (*AssetToken, error) {
	query := `SELECT token_id, owner, asset_value, last_sale_price, created_at, updated_at FROM asset_tokens WHERE token_id=?`
	row := s.DB.QueryRow(query, tokenID)
	token := &AssetToken{}
	err := row.Scan(&token.TokenID, &token.Owner, &token.AssetValue, &token.LastSalePrice, &token.CreatedAt, &token.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("No asset token found with ID %s", tokenID)
			return nil, nil
		}
		log.Printf("Error retrieving asset token %s: %v", tokenID, err)
		return nil, fmt.Errorf("error retrieving asset token: %w", err)
	}
	log.Printf("Asset token %s retrieved successfully", token.TokenID)
	return token, nil
}
