package syn131

import (
    "database/sql"
    "log"
    "sync"
    "time"
)

// Token represents an intangible asset on the blockchain with versatile use-cases.
type Token struct {
    ID          string    `json:"id"`
    Owner       string    `json:"owner"`
    AssetValue  float64   `json:"asset_value"`
    SalePrice   float64   `json:"sale_price"`
    AssetType   string    `json:"asset_type"`
    Description string    `json:"description"`
    Licensing   string    `json:"licensing"`
    RentalTerms string    `json:"rental_terms"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
    mutex       sync.Mutex
}

// TokenRepository handles the storage, retrieval, and management of tokens.
type TokenRepository struct {
    DB *sql.DB
}

// NewTokenRepository creates a new repository for managing tokens using the provided DB.
func NewTokenRepository(db *sql.DB) *TokenRepository {
    return &TokenRepository{DB: db}
}

// CreateToken initializes a new token in the repository with all its properties.
func (repo *TokenRepository) CreateToken(token *Token) error {
    query := `INSERT INTO tokens (id, owner, asset_value, sale_price, asset_type, description, licensing, rental_terms, created_at, updated_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    _, err := repo.DB.Exec(query, token.ID, token.Owner, token.AssetValue, token.SalePrice, token.AssetType, token.Description, token.Licensing, token.RentalTerms, time.Now(), time.Now())
    if err != nil {
        log.Printf("Failed to create token: %v", err)
        return err
    }
    log.Printf("Token created with ID: %s", token.ID)
    return nil
}

// UpdateToken updates the details of an existing token in the database.
func (repo *TokenRepository) UpdateToken(token *Token) error {
    token.mutex.Lock()
    defer token.mutex.Unlock()

    query := `UPDATE tokens SET owner=?, asset_value=?, sale_price=?, asset_type=?, description=?, licensing=?, rental_terms=?, updated_at=? WHERE id=?`
    _, err := repo.DB.Exec(query, token.Owner, token.AssetValue, token.SalePrice, token.AssetType, token.Description, token.Licensing, token.RentalTerms, time.Now(), token.ID)
    if err != nil {
        log.Printf("Failed to update token: %v", err)
        return err
    }
    log.Printf("Token updated with ID: %s", token.ID)
    return nil
}

// FetchToken retrieves a token by its ID.
func (repo *TokenRepository) FetchToken(id string) (*Token, error) {
    query := `SELECT id, owner, asset_value, sale_price, asset_type, description, licensing, rental_terms FROM tokens WHERE id=?`
    row := repo.DB.QueryRow(query, id)
    token := &Token{}
    if err := row.Scan(&token.ID, &token.Owner, &token.AssetValue, &token.SalePrice, &token.AssetType, &token.Description, &token.Licensing, &token.RentalTerms); err != nil {
        log.Printf("Failed to fetch token: %v", err)
        return nil, err
    }
    return token, nil
}

// DeleteToken removes a token from the database.
func (repo *TokenRepository) DeleteToken(id string) error {
    query := `DELETE FROM tokens WHERE id=?`
    _, err := repo.DB.Exec(query, id)
    if err != nil {
        log.Printf("Failed to delete token: %v", err)
        return err
    }
    log.Printf("Token deleted with ID: %s", id)
    return nil
}

// AdjustAssetValue modifies the asset value of a token.
func (token *Token) AdjustAssetValue(newValue float64) {
    token.mutex.Lock()
    defer token.mutex.Unlock()
    token.AssetValue = newValue
    log.Printf("Asset value adjusted for token %s to %f", token.ID, newValue)
}

// SetSalePrice sets the sale price of the token.
func (token *Token) SetSalePrice(newPrice float64) {
    token.mutex.Lock()
    defer token.mutex.Unlock()
    token.SalePrice = newPrice
    log.Printf("Sale price set for token %s to %f", token.ID, newPrice)
}
