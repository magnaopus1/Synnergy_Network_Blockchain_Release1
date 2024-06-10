package syn800

import (
    "database/sql"
    "log"

    _ "github.com/lib/pq" // PostgreSQL driver
)

// Storage handles database operations for asset-backed tokens.
type Storage struct {
    db *sql.DB
}

// NewStorage initializes a new Storage instance.
func NewStorage(dataSourceName string) (*Storage, error) {
    db, err := sql.Open("postgres", dataSourceName)
    if err != nil {
        log.Printf("Failed to open database connection: %v", err)
        return nil, err
    }

    if err = db.Ping(); err != nil {
        log.Printf("Failed to ping database: %v", err)
        return nil, err
    }

    log.Println("Database connection successfully established.")
    return &Storage{db: db}, nil
}

// SaveToken persists a new token or updates an existing one in the database.
func (s *Storage) SaveToken(t *Token) error {
    query := `
        INSERT INTO tokens (id, owner, shares, asset_description, asset_value, asset_location, created_at, last_updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (id) DO UPDATE
        SET owner = EXCLUDED.owner,
            shares = EXCLUDED.shares,
            asset_description = EXCLUDED.asset_description,
            asset_value = EXCLUDED.asset_value,
            asset_location = EXCLUDED.asset_location,
            last_updated_at = EXCLUDED.last_updated_at;
    `
    _, err := s.db.Exec(query, t.ID, t.Owner, t.Shares, t.Asset.Description, t.Asset.Value, t.Asset.Location, t.CreatedAt, t.LastUpdatedAt)
    if err != nil {
        log.Printf("Failed to save token %s: %v", t.ID, err)
        return err
    }

    log.Printf("Token %s successfully saved or updated.", t.ID)
    return nil
}

// GetToken retrieves a token by its ID from the database.
func (s *Storage) GetToken(id string) (*Token, error) {
    query := `
        SELECT id, owner, shares, asset_description, asset_value, asset_location, created_at, last_updated_at
        FROM tokens
        WHERE id = $1;
    `
    row := s.db.QueryRow(query, id)

    var t Token
    err := row.Scan(&t.ID, &t.Owner, &t.Shares, &t.Asset.Description, &t.Asset.Value, &t.Asset.Location, &t.CreatedAt, &t.LastUpdatedAt)
    if err != nil {
        log.Printf("Failed to retrieve token %s: %v", id, err)
        return nil, err
    }

    log.Printf("Token %s retrieved successfully.", id)
    return &t, nil
}

// DeleteToken removes a token from the database.
func (s *Storage) DeleteToken(id string) error {
    query := "DELETE FROM tokens WHERE id = $1;"
    _, err := s.db.Exec(query, id)
    if err != nil {
        log.Printf("Failed to delete token %s: %v", id, err)
        return err
    }

    log.Printf("Token %s deleted successfully.", id)
    return nil
}
