package syn1200

import (
	"database/sql"
	"fmt"
	"log"
)

// TokenStorage manages database operations for SYN1200 tokens.
type TokenStorage struct {
	DB *sql.DB
}

// NewTokenStorage initializes a new storage instance with a database connection.
func NewTokenStorage(db *sql.DB) *TokenStorage {
	return &TokenStorage{DB: db}
}

// SaveToken persists a new token or updates an existing one in the database.
func (ts *TokenStorage) SaveToken(token *InteroperableToken) error {
	query := `INSERT INTO tokens (id, owner, supply, creation_date) VALUES (?, ?, ?, ?)
			  ON DUPLICATE KEY UPDATE owner = ?, supply = ?`
	_, err := ts.DB.Exec(query, token.ID, token.Owner, token.Supply, token.CreationDate, token.Owner, token.Supply)
	if err != nil {
		log.Printf("Failed to save token %s: %v", token.ID, err)
		return err
	}
	log.Printf("Token %s saved or updated successfully", token.ID)
	return nil
}

// GetToken retrieves a token's details from the database.
func (ts *TokenStorage) GetToken(id string) (*InteroperableToken, error) {
	query := `SELECT id, owner, supply, creation_date FROM tokens WHERE id = ?`
	row := ts.DB.QueryRow(query, id)
	token := &InteroperableToken{}

	if err := row.Scan(&token.ID, &token.Owner, &token.Supply, &token.CreationDate); err != nil {
		log.Printf("Failed to retrieve token %s: %v", id, err)
		return nil, err
	}
	log.Printf("Token %s retrieved successfully", token.ID)
	return token, nil
}

// DeleteToken removes a token from the database.
func (ts *TokenStorage) DeleteToken(id string) error {
	query := `DELETE FROM tokens WHERE id = ?`
	_, err := ts.DB.Exec(query, id)
	if err != nil {
		log.Printf("Failed to delete token %s: %v", id, err)
		return err
	}
	log.Printf("Token %s deleted successfully", id)
	return nil
}

// LogAtomicSwap records details of an atomic swap in the database.
func (ts *TokenStorage) LogAtomicSwap(swap *AtomicSwap) error {
	query := `INSERT INTO atomic_swaps (swap_id, partner_chain, initiated, completed, status) VALUES (?, ?, ?, ?, ?)`
	_, err := ts.DB.Exec(query, swap.SwapID, swap.PartnerChain, swap.Initiated, swap.Completed, swap.Status)
	if err != nil {
		log.Printf("Failed to log atomic swap %s: %v", swap.SwapID, err)
		return err
	}
	log.Printf("Atomic swap %s logged successfully", swap.SwapID)
	return nil
}

// Example of setting up and using the token storage.
func ExampleStorageUsage(db *sql.DB) {
	storage := NewTokenStorage(db)
	token := NewInteroperableToken("tokenXYZ", "user123", 1000, []string{"Ethereum", "Polygon"})

	if err := storage.SaveToken(token); err != nil {
		log.Println("Error saving token:", err)
	}

	if retrievedToken, err := storage.GetToken("tokenXYZ"); err != nil {
		log.Println("Error retrieving token:", err)
	} else {
		fmt.Println("Retrieved Token:", retrievedToken)
	}

	if err := storage.DeleteToken("tokenXYZ"); err != nil {
		log.Println("Error deleting token:", err)
	}
}
