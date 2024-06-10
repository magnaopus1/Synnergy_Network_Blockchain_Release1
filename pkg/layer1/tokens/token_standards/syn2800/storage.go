package syn2800

import (
	"database/sql"
	"encoding/json"
	"errors"

	_ "github.com/mattn/go-sqlite3" // Import go-sqlite3 library
)

// Storage handles interactions with the database.
type Storage struct {
	DB *sql.DB
}

// NewStorage initializes a new Storage instance with a database connection.
func NewStorage(dataSourceName string) (*Storage, error) {
	db, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		return nil, err
	}
	return &Storage{DB: db}, nil
}

// InitializeDB sets up the necessary database tables if they do not exist.
func (s *Storage) InitializeDB() error {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS life_insurance_tokens (
		token_id TEXT PRIMARY KEY,
		data BLOB NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err := s.DB.Exec(createTableSQL)
	if err != nil {
		return err
	}
	return nil
}

// SaveToken stores a LifeInsuranceToken in the database.
func (s *Storage) SaveToken(token LifeInsuranceToken) error {
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}

	_, err = s.DB.Exec("INSERT INTO life_insurance_tokens (token_id, data) VALUES (?, ?)", token.TokenID, data)
	if err != nil {
		return err
	}
	return nil
}

// GetToken retrieves a LifeInsuranceToken from the database.
func (s *Storage) GetToken(tokenID string) (LifeInsuranceToken, error) {
	var token LifeInsuranceToken
	var data []byte

	row := s.DB.QueryRow("SELECT data FROM life_insurance_tokens WHERE token_id = ?", tokenID)
	if err := row.Scan(&data); err != nil {
		if err == sql.ErrNoRows {
			return token, errors.New("no token found with the given ID")
		}
		return token, err
	}

	if err := json.Unmarshal(data, &token); err != nil {
		return token, err
	}
	return token, nil
}

// UpdateToken updates an existing LifeInsuranceToken in the database.
func (s *Storage) UpdateToken(tokenID string, token LifeInsuranceToken) error {
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}

	_, err = s.DB.Exec("UPDATE life_insurance_tokens SET data = ? WHERE token_id = ?", data, tokenID)
	if err != nil {
		return err
	}
	return nil
}

// DeleteToken removes a LifeInsuranceToken from the database.
func (s *Storage) DeleteToken(tokenID string) error {
	_, err := s.DB.Exec("DELETE FROM life_insurance_tokens WHERE token_id = ?", tokenID)
	if err != nil {
		return err
	}
	return nil
}

// ListTokens retrieves all active tokens from the database.
func (s *Storage) ListTokens() ([]LifeInsuranceToken, error) {
	var tokens []LifeInsuranceToken
	rows, err := s.DB.Query("SELECT data FROM life_insurance_tokens")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			continue
		}
		var token LifeInsuranceToken
		if err := json.Unmarshal(data, &token); err != nil {
			continue
		}
		if token.Active {
			tokens = append(tokens, token)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tokens, nil
}

