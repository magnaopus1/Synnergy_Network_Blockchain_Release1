package syn3100

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "log"
    "time"
    _ "github.com/mattn/go-sqlite3" // SQLite is used for demonstration purposes; import only for side effects
)

// Storage represents the database client for Employment Tokens
type Storage struct {
    DB *sql.DB
}

func NewStorage(dataSourceName string) (*Storage, error) {
    db, err := sql.Open("sqlite3", dataSourceName)
    if err != nil {
        return nil, err
    }

    if err := createTables(db); err != nil {
        return nil, err
    }

    return &Storage{DB: db}, nil
}

func createTables(db *sql.DB) error {
    query := `
    CREATE TABLE IF NOT EXISTS employment_tokens (
        token_id TEXT PRIMARY KEY,
        contract_data TEXT NOT NULL,
        issued_date DATETIME NOT NULL,
        active BOOLEAN NOT NULL
    );
    `
    _, err := db.Exec(query)
    return err
}

// IssueToken handles the creation and storage of new EmploymentToken
func (s *Storage) IssueToken(contract EmploymentContract) (*EmploymentToken, error) {
    tokenID := fmt.Sprintf("token-%d", time.Now().UnixNano()) // Example token ID generation
    token := &EmploymentToken{
        TokenID:     tokenID,
        Contract:    contract,
        IssuedDate:  time.Now(),
    }
    contract.IsActive = true // Activate the contract
    err := s.SaveToken(token)
    return token, err
}

// UpdateContract wraps UpdateToken with specific handling for contract updates
func (s *Storage) UpdateContract(tokenID string, updates map[string]interface{}) error {
    token, err := s.GetToken(tokenID)
    if err != nil {
        return err
    }

    // Apply updates to the token's contract
    for key, value := range updates {
        switch key {
        case "IsActive":
            isActive, ok := value.(bool)
            if ok {
                token.Contract.IsActive = isActive
            }
        }
    }

    return s.UpdateToken(tokenID, &token.Contract)
}

// DeactivateContract specifically sets a contract's active status to false
func (s *Storage) DeactivateContract(tokenID string) error {
    token, err := s.GetToken(tokenID)
    if err != nil {
        return err
    }

    token.Contract.IsActive = false
    return s.UpdateToken(tokenID, &token.Contract)
}

// SaveToken stores a new EmploymentToken in the database
func (s *Storage) SaveToken(token *EmploymentToken) error {
    contractData, err := json.Marshal(token.Contract)
    if err != nil {
        return err
    }

    query := "INSERT INTO employment_tokens (token_id, contract_data, issued_date, active) VALUES (?, ?, ?, ?)"
    _, err = s.DB.Exec(query, token.TokenID, string(contractData), token.IssuedDate, token.Contract.IsActive)
    return err
}

// UpdateToken updates an existing EmploymentToken in the database
func (s *Storage) UpdateToken(tokenID string, contract *EmploymentContract) error {
    contractData, err := json.Marshal(contract)
    if err != nil {
        return err
    }

    query := "UPDATE employment_tokens SET contract_data = ?, active = ? WHERE token_id = ?"
    _, err = s.DB.Exec(query, string(contractData), contract.IsActive, tokenID)
    return err
}

// GetToken retrieves an EmploymentToken by its ID
func (s *Storage) GetToken(tokenID string) (*EmploymentToken, error) {
    query := "SELECT token_id, contract_data, issued_date, active FROM employment_tokens WHERE token_id = ?"
    row := s.DB.QueryRow(query, tokenID)

    var token EmploymentToken
    var contractData string

    if err := row.Scan(&token.TokenID, &contractData, &token.IssuedDate, &token.Contract.IsActive); err != nil {
        return nil, err
    }

    if err := json.Unmarshal([]byte(contractData), &token.Contract); err != nil {
        return nil, err
    }

    return &token, nil
}

// ListActiveTokens returns all active EmploymentTokens
func (s *Storage) ListActiveTokens() ([]EmploymentToken, error) {
    query := "SELECT token_id, contract_data, issued_date, active FROM employment_tokens WHERE active = TRUE"
    rows, err := s.DB.Query(query)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var tokens []EmploymentToken
    for rows.Next() {
        var token EmploymentToken
        var contractData string
        if err := rows.Scan(&token.TokenID, &contractData, &token.IssuedDate, &token.Contract.IsActive); err != nil {
            log.Println("Error scanning token:", err)
            continue
        }

        if err := json.Unmarshal([]byte(contractData), &token.Contract); err != nil {
            log.Println("Error unmarshaling contract data:", err)
            continue
        }

        tokens = append(tokens, token)
    }

    if err := rows.Err(); err != nil {
        return nil, err
    }

    return tokens, nil
}
