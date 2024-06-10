package syn1500

import (
	"database/sql"
	"fmt"
	"log"
	"sync"

	_ "github.com/mattn/go-sqlite3" // SQLite is used for this example; adjust as necessary for your DB
)

// TokenStorage manages the persistence layer for Reputation Tokens.
type TokenStorage struct {
	db    *sql.DB
	mutex sync.Mutex
}

// NewTokenStorage initializes a connection to the database and ensures that the necessary tables are created.
func NewTokenStorage(dataSourceName string) *TokenStorage {
	db, err := sql.Open("sqlite3", dataSourceName)
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
	storage := &TokenStorage{db: db}
	storage.initDB()
	return storage
}

// initDB creates the tables if they do not already exist.
func (ts *TokenStorage) initDB() {
	query := `
	CREATE TABLE IF NOT EXISTS reputation_tokens (
		id TEXT PRIMARY KEY,
		owner TEXT NOT NULL,
		reputation_score INTEGER NOT NULL,
		trust_level TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS reputation_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		token_id TEXT NOT NULL,
		description TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(token_id) REFERENCES reputation_tokens(id)
	);
	`
	_, err := ts.db.Exec(query)
	if err != nil {
		log.Fatal("Failed to create tables:", err)
	}
}

// SaveToken inserts a new Reputation Token into the database.
func (ts *TokenStorage) SaveToken(token *ReputationToken) error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	query := `INSERT INTO reputation_tokens (id, owner, reputation_score, trust_level) VALUES (?, ?, ?, ?)`
	_, err := ts.db.Exec(query, token.ID, token.Owner, token.ReputationScore, token.TrustLevel)
	if err != nil {
		log.Printf("Failed to save token %s: %v", token.ID, err)
		return fmt.Errorf("failed to save token: %w", err)
	}
	log.Printf("Token %s saved successfully", token.ID)
	return nil
}

// UpdateToken updates the details of an existing Reputation Token.
func (ts *TokenStorage) UpdateToken(token *ReputationToken) error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	query := `UPDATE reputation_tokens SET owner = ?, reputation_score = ?, trust_level = ? WHERE id = ?`
	_, err := ts.db.Exec(query, token.Owner, token.ReputationScore, token.TrustLevel, token.ID)
	if err != nil {
		log.Printf("Failed to update token %s: %v", token.ID, err)
		return fmt.Errorf("failed to update token: %w", err)
	}
	log.Printf("Token %s updated successfully", token.ID)
	return nil
}

// LogEvent adds a new event to the reputation events table.
func (ts *TokenStorage) LogEvent(tokenID, description string) error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	query := `INSERT INTO reputation_events (token_id, description) VALUES (?, ?)`
	_, err := ts.db.Exec(query, tokenID, description)
	if err != nil {
		log.Printf("Failed to log event for token %s: %v", tokenID, err)
		return fmt.Errorf("failed to log event: %w", err)
	}
	log.Printf("Event logged for token %s: %s", tokenID, description)
	return nil
}

// GetTokenDetails retrieves the details of a specific token, including events.
func (ts *TokenStorage) GetTokenDetails(tokenID string) (*ReputationToken, []ReputationEvent, error) {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	// Retrieve the main token details
	tokenQuery := `SELECT id, owner, reputation_score, trust_level FROM reputation_tokens WHERE id = ?`
	tokenRow := ts.db.QueryRow(tokenQuery, tokenID)
	token := &ReputationToken{}
	err := tokenRow.Scan(&token.ID, &token.Owner, &token.ReputationScore, &token.TrustLevel)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, fmt.Errorf("no token found with ID %s", tokenID)
		}
		return nil, nil, fmt.Errorf("error retrieving token details: %w", err)
	}

	// Retrieve all related events
	eventsQuery := `SELECT description, timestamp FROM reputation_events WHERE token_id = ?`
	rows, err := ts.db.Query(eventsQuery, tokenID)
	if err != nil {
		return token, nil, fmt.Errorf("error retrieving events for token %s: %w", tokenID, err)
	}
	defer rows.Close()

	var events []ReputationEvent
	for rows.Next() {
		var event ReputationEvent
		if err := rows.Scan(&event.Description, &event.Date); err != nil {
			continue // Skip on error, could log or handle differently
		}
		events = append(events, event)
	}

	return token, events, nil
}

