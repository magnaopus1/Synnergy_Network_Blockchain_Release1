package syn70

import (
	"database/sql"
	"log"
)

// Storage manages the database operations for SYN70 tokens.
type Storage struct {
	DB *sql.DB
}

// NewStorage creates a new Storage instance with a database connection.
func NewStorage(db *sql.DB) *Storage {
	return &Storage{DB: db}
}

// SaveToken persists a token in the database.
func (s *Storage) SaveToken(token *Token) error {
	query := `INSERT INTO tokens (id, name, owner, balance, game_id) VALUES (?, ?, ?, ?, ?)
	ON DUPLICATE KEY UPDATE name=VALUES(name), owner=VALUES(owner), balance=VALUES(balance), game_id=VALUES(game_id)`
	_, err := s.DB.Exec(query, token.ID, token.Name, token.Owner, token.Balance, token.GameID)
	if err != nil {
		log.Printf("Failed to save token %s: %v", token.ID, err)
		return err
	}
	log.Printf("Token %s successfully saved/updated in the database.", token.ID)
	return nil
}

// GetToken retrieves a token by its ID from the database.
func (s *Storage) GetToken(id string) (*Token, error) {
	query := `SELECT id, name, owner, balance, game_id FROM tokens WHERE id = ?`
	row := s.DB.QueryRow(query, id)
	token := &Token{}
	err := row.Scan(&token.ID, &token.Name, &token.Owner, &token.Balance, &token.GameID)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("No token found with ID %s", id)
			return nil, err
		}
		log.Printf("Failed to retrieve token %s: %v", id, err)
		return nil, err
	}
	token.DB = s.DB
	log.Printf("Token %s retrieved from the database.", id)
	return token, nil
}

// DeleteToken removes a token from the database.
func (s *Storage) DeleteToken(id string) error {
	query := `DELETE FROM tokens WHERE id = ?`
	_, err := s.DB.Exec(query, id)
	if err != nil {
		log.Printf("Failed to delete token %s: %v", id, err)
		return err
	}
	log.Printf("Token %s deleted from the database.", id)
	return nil
}

// ListTokens returns all tokens associated with a specific game.
func (s *Storage) ListTokens(gameID string) ([]*Token, error) {
	query := `SELECT id, name, owner, balance, game_id FROM tokens WHERE game_id = ?`
	rows, err := s.DB.Query(query, gameID)
	if err != nil {
		log.Printf("Failed to list tokens for game %s: %v", gameID, err)
		return nil, err
	}
	defer rows.Close()

	var tokens []*Token
	for rows.Next() {
		token := &Token{}
		if err := rows.Scan(&token.ID, &token.Name, &token.Owner, &token.Balance, &token.GameID); err != nil {
			log.Printf("Error scanning token: %v", err)
			continue // Log and continue to process other tokens
		}
		token.DB = s.DB
		tokens = append(tokens, token)
	}
	if err = rows.Err(); err != nil {
		log.Printf("Error during rows iteration: %v", err)
		return nil, err
	}
	log.Printf("Successfully listed %d tokens for game %s.", len(tokens), gameID)
	return tokens, nil
}
