package syn1300

import (
	"database/sql"
	"fmt"
	"log"
	"sync"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// TokenStorage handles the database operations for SupplyChainAsset tokens.
type TokenStorage struct {
	db   *sql.DB
	mutex sync.Mutex
}

// NewTokenStorage creates a new instance of TokenStorage.
func NewTokenStorage(db *sql.DB) *TokenStorage {
	return &TokenStorage{db: db}
}

// SaveToken inserts a new token into the database.
func (ts *TokenStorage) SaveToken(token *Token) error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	query := `INSERT INTO tokens (id, owner, creation_date) VALUES ($1, $2, $3)`
	_, err := ts.db.Exec(query, token.ID, token.Owner, token.CreationDate)
	if err != nil {
		log.Printf("Failed to save token: %v", err)
		return fmt.Errorf("save token: %w", err)
	}
	log.Printf("Token %s saved successfully.", token.ID)
	return nil
}

// UpdateToken updates a token's owner in the database.
func (ts *TokenStorage) UpdateTokenOwner(tokenID, newOwner string) error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	query := `UPDATE tokens SET owner = $1 WHERE id = $2`
	_, err := ts.db.Exec(query, newOwner, tokenID)
	if err != nil {
		log.Printf("Failed to update token owner: %v", err)
		return fmt.Errorf("update token owner: %w", err)
	}
	log.Printf("Token %s owner updated successfully.", tokenID)
	return nil
}

// FetchToken retrieves a token's data from the database.
func (ts *TokenStorage) FetchToken(tokenID string) (*Token, error) {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	query := `SELECT id, owner, creation_date FROM tokens WHERE id = $1`
	row := ts.db.QueryRow(query, tokenID)

	var token Token
	err := row.Scan(&token.ID, &token.Owner, &token.CreationDate)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("token %s not found", tokenID)
		}
		log.Printf("Failed to fetch token: %v", err)
		return nil, fmt.Errorf("fetch token: %w", err)
	}

	// Load assets and history as well if necessary
	// This part is omitted for brevity, assume similar fetches for assets and history

	log.Printf("Token %s retrieved successfully.", token.ID)
	return &token, nil
}

// DeleteToken removes a token from the database.
func (ts *TokenStorage) DeleteToken(tokenID string) error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	query := `DELETE FROM tokens WHERE id = $1`
	_, err := ts.db.Exec(query, tokenID)
	if err != nil {
		log.Printf("Failed to delete token: %v", err)
		return fmt.Errorf("delete token: %w", err)
	}
	log.Printf("Token %s deleted successfully.", tokenID)
	return nil
}

// Example of initializing TokenStorage and using it
func ExampleTokenStorageUsage(db *sql.DB) {
	storage := NewTokenStorage(db)
	token := NewToken("token001", "owner001")
	if err := storage.SaveToken(token); err != nil {
		log.Printf("Error saving token: %v", err)
	}
}
