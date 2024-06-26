package syn2900

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "log"

    _ "github.com/lib/pq" // PostgreSQL driver
)

// Storage defines the required database operations.
type Storage interface {
    SaveToken(token InsuranceToken) error
    GetToken(tokenID string) (InsuranceToken, error)
    UpdateToken(token InsuranceToken) error
    DeleteToken(tokenID string) error
    ListTokens() ([]InsuranceToken, error)
}

// DBStorage manages the interaction with the database.
type DBStorage struct {
    DB *sql.DB
}

// NewDBStorage initializes a new DBStorage instance with a database connection.
func NewDBStorage(dataSourceName string) (*DBStorage, error) {
    db, err := sql.Open("postgres", dataSourceName)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to database: %v", err)
    }
    if err := db.Ping(); err != nil {
        return nil, fmt.Errorf("failed to ping database: %v", err)
    }
    return &DBStorage{DB: db}, nil
}

// Close handles the closure of the database connection.
func (s *DBStorage) Close() error {
    return s.DB.Close()
}

// Implement all methods defined in the Storage interface
func (s *DBStorage) SaveToken(token InsuranceToken) error {
    data, err := json.Marshal(token)
    if err != nil {
        return fmt.Errorf("error marshaling token: %v", err)
    }
    _, err = s.DB.Exec("INSERT INTO insurance_tokens (token_id, token_data) VALUES ($1, $2)", token.TokenID, data)
    return err
}

func (s *DBStorage) GetToken(tokenID string) (InsuranceToken, error) {
    var data []byte
    token := InsuranceToken{}

    row := s.DB.QueryRow("SELECT token_data FROM insurance_tokens WHERE token_id = $1", tokenID)
    err := row.Scan(&data)
    if err != nil {
        if err == sql.ErrNoRows {
            return token, fmt.Errorf("no token found with ID: %s", tokenID)
        }
        return token, fmt.Errorf("error querying token from database: %v", err)
    }

    err = json.Unmarshal(data, &token)
    if err != nil {
        return token, fmt.Errorf("error unmarshaling token data: %v", err)
    }

    return token, nil
}

func (s *DBStorage) UpdateToken(token InsuranceToken) error {
    data, err := json.Marshal(token)
    if err != nil {
        return fmt.Errorf("error marshaling token: %v", err)
    }

    _, err = s.DB.Exec("UPDATE insurance_tokens SET token_data = $1 WHERE token_id = $2", data, token.TokenID)
    if err != nil {
        return fmt.Errorf("error updating token in database: %v", err)
    }

    return nil
}

func (s *DBStorage) DeleteToken(tokenID string) error {
    _, err := s.DB.Exec("DELETE FROM insurance_tokens WHERE token_id = $1", tokenID)
    if err != nil {
        return fmt.Errorf("error deleting token from database: %v", err)
    }

    return nil
}

func (s *DBStorage) ListTokens() ([]InsuranceToken, error) {
    rows, err := s.DB.Query("SELECT token_data FROM insurance_tokens")
    if err != nil {
        return nil, fmt.Errorf("error retrieving tokens from database: %v", err)
    }
    defer rows.Close()

    var tokens []InsuranceToken
    for rows.Next() {
        var data []byte
        token := InsuranceToken{}

        if err := rows.Scan(&data); err != nil {
            log.Println("Error scanning token data:", err)
            continue
        }

        if err := json.Unmarshal(data, &token); err != nil {
            log.Println("Error unmarshaling token data:", err)
            continue
        }

        tokens = append(tokens, token)
    }

    if err := rows.Err(); err != nil {
        return nil, fmt.Errorf("Error during rows iteration: %v", err)
    }

    return tokens, nil
}
