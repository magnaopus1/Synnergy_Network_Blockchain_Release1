package syn223

import (
	"database/sql"
	"fmt"
	"log"
)

// TokenStorage handles database operations for SYN223 tokens.
type TokenStorage struct {
	DB *sql.DB
}

// NewTokenStorage creates a new instance of TokenStorage.
func NewTokenStorage(db *sql.DB) *TokenStorage {
	return &TokenStorage{DB: db}
}

// StoreTokenBalance updates the balance of a specific address.
func (s *TokenStorage) StoreTokenBalance(address string, balance uint64) error {
	query := "REPLACE INTO token_balances (address, balance) VALUES (?, ?)"
	_, err := s.DB.Exec(query, address, balance)
	if err != nil {
		log.Printf("Error updating balance for address %s: %v", address, err)
		return fmt.Errorf("error storing token balance: %w", err)
	}
	log.Printf("Updated balance for address %s to %d", address, balance)
	return nil
}

// GetTokenBalance retrieves the balance of a specific address.
func (s *TokenStorage) GetTokenBalance(address string) (uint64, error) {
	query := "SELECT balance FROM token_balances WHERE address = ?"
	var balance uint64
	err := s.DB.QueryRow(query, address).Scan(&balance)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("No balance record found for address %s", address)
			return 0, nil // Returning 0 if no balance is found
		}
		log.Printf("Error retrieving balance for address %s: %v", address, err)
		return 0, fmt.Errorf("error retrieving token balance: %w", err)
	}
	log.Printf("Retrieved balance for address %s: %d", address, balance)
	return balance, nil
}

// StoreAllowance sets the allowance a holder grants to another address.
func (s *TokenStorage) StoreAllowance(owner, spender string, allowance uint64) error {
	query := "REPLACE INTO allowances (owner, spender, allowance) VALUES (?, ?, ?)"
	_, err := s.DB.Exec(query, owner, spender, allowance)
	if err != nil {
		log.Printf("Error setting allowance from %s to %s: %v", owner, spender, err)
		return fmt.Errorf("error storing allowance: %w", err)
	}
	log.Printf("Allowance set for spender %s by owner %s: %d", spender, owner, allowance)
	return nil
}

// GetAllowance retrieves the amount an owner has allowed a spender to use.
func (s *TokenStorage) GetAllowance(owner, spender string) (uint64, error) {
	query := "SELECT allowance FROM allowances WHERE owner = ? AND spender = ?"
	var allowance uint64
	err := s.DB.QueryRow(query, owner, spender).Scan(&allowance)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("No allowance record found for owner %s and spender %s", owner, spender)
			return 0, nil // Returning 0 if no allowance is found
		}
		log.Printf("Error retrieving allowance for owner %s and spender %s: %v", owner, spender, err)
		return 0, fmt.Errorf("error retrieving allowance: %w", err)
	}
	log.Printf("Retrieved allowance for spender %s by owner %s: %d", spender, owner, allowance)
	return allowance, nil
}
