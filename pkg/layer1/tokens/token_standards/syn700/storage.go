package syn700

import (
    "database/sql"
    "fmt"
    "log"
)

// Storage handles the database operations for SYN700 tokens.
type Storage struct {
    DB *sql.DB
}

// NewStorage initializes a new storage handler.
func NewStorage(db *sql.DB) *Storage {
    return &Storage{DB: db}
}

// CreateToken inserts a new SYN700 token into the database.
func (s *Storage) CreateToken(token *Token) error {
    query := `INSERT INTO tokens (id, owner, title, description, registered) VALUES (?, ?, ?, ?, ?)`
    _, err := s.DB.Exec(query, token.ID, token.Owner, token.IP.Title, token.IP.Description, token.IP.Registered)
    if err != nil {
        log.Printf("Error creating token in database: %v", err)
        return fmt.Errorf("failed to create token: %w", err)
    }
    log.Printf("Token %s created successfully in the database.", token.ID)
    return nil
}

// TransferOwnership updates the owner of a specific token in the database.
func (s *Storage) TransferOwnership(tokenID, newOwner string) error {
    query := `UPDATE tokens SET owner=? WHERE id=?`
    _, err := s.DB.Exec(query, newOwner, tokenID)
    if err != nil {
        log.Printf("Error transferring ownership of token %s: %v", tokenID, err)
        return fmt.Errorf("failed to transfer ownership: %w", err)
    }
    log.Printf("Ownership of token %s transferred to %s.", tokenID, newOwner)
    return nil
}

// UpdateSalePrice updates the sale price of a specific token in the database.
func (s *Storage) UpdateSalePrice(tokenID string, newSalePrice float64) error {
    query := `UPDATE tokens SET sale_price=? WHERE id=?`
    _, err := s.DB.Exec(query, newSalePrice, tokenID)
    if err != nil {
        log.Printf("Error updating sale price of token %s: %v", tokenID, err)
        return fmt.Errorf("failed to update sale price: %w", err)
    }
    log.Printf("Sale price of token %s updated to %.2f.", tokenID, newSalePrice)
    return nil
}

// FetchToken retrieves a token by its ID from the database.
func (s *Storage) FetchToken(id string) (*Token, error) {
    query := `SELECT id, owner, title, description, registered FROM tokens WHERE id=?`
    row := s.DB.QueryRow(query, id)
    var token Token
    if err := row.Scan(&token.ID, &token.Owner, &token.IP.Title, &token.IP.Description, &token.IP.Registered); err != nil {
        log.Printf("Error fetching token %s: %v", id, err)
        return nil, fmt.Errorf("failed to fetch token: %w", err)
    }
    log.Printf("Token %s fetched successfully.", token.ID)
    return &token, nil
}

// DeleteToken removes a token from the database.
func (s *Storage) DeleteToken(id string) error {
    query := `DELETE FROM tokens WHERE id=?`
    _, err := s.DB.Exec(query, id)
    if err != nil {
        log.Printf("Error deleting token %s: %v", id, err)
        return fmt.Errorf("failed to delete token: %w", err)
    }
    log.Printf("Token %s deleted successfully.", id)
    return nil
}
