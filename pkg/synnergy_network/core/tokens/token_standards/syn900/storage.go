package syn900

import (
    "database/sql"
    "fmt"
    "log"
    "time"

    _ "github.com/mattn/go-sqlite3" // Using SQLite for simplicity
)

// Storage handles database operations for SYN900 tokens.
type Storage struct {
    DB *sql.DB
}

// NewStorage creates a new storage instance with a database connection.
func NewStorage(db *sql.DB) *Storage {
    return &Storage{DB: db}
}

// SaveToken saves a new identity token to the database.
func (s *Storage) SaveToken(token *Token) error {
    query := `INSERT INTO identity_tokens (id, owner, full_name, date_of_birth, nationality, image_hash, address, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    _, err := s.DB.Exec(query, token.ID, token.Owner, token.Identity.FullName, token.Identity.DateOfBirth, token.Identity.Nationality, token.Identity.ImageHash, token.Identity.Address, token.CreatedAt)
    if err != nil {
        log.Printf("Failed to save token %s: %v", token.ID, err)
        return fmt.Errorf("failed to save token: %w", err)
    }
    log.Printf("Token %s successfully saved to the database", token.ID)
    return nil
}

// GetToken retrieves an identity token from the database.
func (s *Storage) GetToken(id string) (*Token, error) {
    query := `SELECT id, owner, full_name, date_of_birth, nationality, image_hash, address, created_at FROM identity_tokens WHERE id = ?`
    row := s.DB.QueryRow(query, id)
    var token Token
    var dob time.Time
    err := row.Scan(&token.ID, &token.Owner, &token.Identity.FullName, &dob, &token.Identity.Nationality, &token.Identity.ImageHash, &token.Identity.Address, &token.CreatedAt)
    if err != nil {
        log.Printf("Failed to retrieve token %s: %v", id, err)
        return nil, fmt.Errorf("failed to retrieve token: %w", err)
    }
    token.Identity.DateOfBirth = dob
    log.Printf("Token %s retrieved from the database", token.ID)
    return &token, nil
}

// UpdateToken updates an existing identity token in the database.
func (s *Storage) UpdateToken(token *Token) error {
    query := `UPDATE identity_tokens SET owner = ?, full_name = ?, date_of_birth = ?, nationality = ?, image_hash = ?, address = ? WHERE id = ?`
    _, err := s.DB.Exec(query, token.Owner, token.Identity.FullName, token.Identity.DateOfBirth, token.Identity.Nationality, token.Identity.ImageHash, token.Identity.Address, token.ID)
    if err != nil {
        log.Printf("Failed to update token %s: %v", token.ID, err)
        return fmt.Errorf("failed to update token: %w", err)
    }
    log.Printf("Token %s updated in the database", token.ID)
    return nil
}

// DeleteToken deletes an identity token from the database.
func (s *Storage) DeleteToken(id string) error {
    query := `DELETE FROM identity_tokens WHERE id = ?`
    _, err := s.DB.Exec(query, id)
    if err != nil {
        log.Printf("Failed to delete token %s: %v", id, err)
        return fmt.Errorf("failed to delete token: %w", err)
    }
    log.Printf("Token %s deleted from the database", id)
    return nil
}
