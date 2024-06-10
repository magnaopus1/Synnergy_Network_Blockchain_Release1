package syn1401

import (
    "database/sql"
    "fmt"
    "log"
)

// TokenStorage manages the storage of Investment Tokens.
type TokenStorage struct {
    db *sql.DB
}

// NewTokenStorage creates a new storage handler for investment tokens.
func NewTokenStorage(db *sql.DB) *TokenStorage {
    return &TokenStorage{db: db}
}

// SaveToken persists a new investment token in the database.
func (ts *TokenStorage) SaveToken(token *InvestmentToken) error {
    query := `INSERT INTO investment_tokens (id, owner, principal, interest_rate, start_date, maturity_date, yield) VALUES (?, ?, ?, ?, ?, ?, ?)`
    _, err := ts.db.Exec(query, token.ID, token.Owner, token.Principal, token.InterestRate, token.StartDate, token.MaturityDate, token.Yield)
    if err != nil {
        log.Printf("Failed to save investment token %s: %v", token.ID, err)
        return fmt.Errorf("failed to save investment token: %w", err)
    }
    log.Printf("Investment token %s saved successfully", token.ID)
    return nil
}

// UpdateToken updates details of an existing investment token.
func (ts *TokenStorage) UpdateToken(token *InvestmentToken) error {
    query := `UPDATE investment_tokens SET owner=?, yield=? WHERE id=?`
    _, err := ts.db.Exec(query, token.Owner, token.Yield, token.ID)
    if err != nil {
        log.Printf("Failed to update investment token %s: %v", token.ID, err)
        return fmt.Errorf("failed to update investment token: %w", err)
    }
    log.Printf("Investment token %s updated successfully", token.ID)
    return nil
}

// FetchToken retrieves an investment token by its ID.
func (ts *TokenStorage) FetchToken(id string) (*InvestmentToken, error) {
    query := `SELECT id, owner, principal, interest_rate, start_date, maturity_date, yield FROM investment_tokens WHERE id=?`
    row := ts.db.QueryRow(query, id)
    var token InvestmentToken
    if err := row.Scan(&token.ID, &token.Owner, &token.Principal, &token.InterestRate, &token.StartDate, &token.MaturityDate, &token.Yield); err != nil {
        log.Printf("Failed to fetch investment token %s: %v", id, err)
        return nil, fmt.Errorf("failed to fetch investment token: %w", err)
    }
    log.Printf("Investment token %s fetched successfully", token.ID)
    return &token, nil
}

// DeleteToken removes a token from the database.
func (ts *TokenStorage) DeleteToken(id string) error {
    query := `DELETE FROM investment_tokens WHERE id=?`
    _, err := ts.db.Exec(query, id)
    if err != nil {
        log.Printf("Failed to delete investment token %s: %v", id, err)
        return fmt.Errorf("failed to delete investment token: %w", err)
    }
    log.Printf("Investment token %s deleted successfully", id)
    return nil
}

// Example of setting up and using TokenStorage
func ExampleStorageUsage(db *sql.DB) {
    storage := NewTokenStorage(db)
    token := NewInvestmentToken("token001", "user001", 1000, 0.05, 365)
    if err := storage.SaveToken(token); err != nil {
        log.Println("Error saving token:", err)
    }

    fetchedToken, err := storage.FetchToken("token001")
    if err != nil {
        log.Println("Error fetching token:", err)
    } else {
        fmt.Printf("Fetched Token: %+v\n", fetchedToken)
    }
}
