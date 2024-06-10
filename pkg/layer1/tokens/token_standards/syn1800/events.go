package syn1800

import (
	"encoding/json"
	"time"
)

// Event Types
const (
	EventCreateAccount  = "CREATE_ACCOUNT"
	EventIssueToken     = "ISSUE_TOKEN"
	EventTransferToken  = "TRANSFER_TOKEN"
	EventTokenBurned    = "TOKEN_BURNED"
	EventTokenMinted    = "TOKEN_MINTED"
)

// Event represents a generic blockchain event for logging purposes.
type Event struct {
	Type      string          `json:"type"`      // Type of event
	Timestamp time.Time       `json:"timestamp"` // Timestamp of the event
	Details   json.RawMessage `json:"details"`   // Details of the event, flexible depending on the type
}

// CreateAccountEventDetails holds data for account creation events.
type CreateAccountEventDetails struct {
	AccountID string `json:"accountId"`
}

// IssueTokenEventDetails holds data for token issuance events.
type IssueTokenEventDetails struct {
	TokenID    string  `json:"tokenId"`
	AccountID  string  `json:"accountId"`
	Amount     float64 `json:"amount"`
	IssuedDate time.Time `json:"issuedDate"`
}

// TransferTokenEventDetails holds data for token transfer events.
type TransferTokenEventDetails struct {
	TokenID   string  `json:"tokenId"`
	From      string  `json:"from"`
	To        string  `json:"to"`
	Amount    float64 `json:"amount"`
	TransferDate time.Time `json:"transferDate"`
}

// TokenBurnedEventDetails holds data for token burn events.
type TokenBurnedEventDetails struct {
	TokenID   string  `json:"tokenId"`
	AccountID string  `json:"accountId"`
	Amount    float64 `json:"amount"`
	BurnDate  time.Time `json:"burnDate"`
}

// TokenMintedEventDetails holds data for token mint events.
type TokenMintedEventDetails struct {
	TokenID   string  `json:"tokenId"`
	AccountID string  `json:"accountId"`
	Amount    float64 `json:"amount"`
	MintDate  time.Time `json:"mintDate"`
}

// NewEvent creates a new event with the given type and details.
func NewEvent(eventType string, details interface{}) (*Event, error) {
	detailsBytes, err := json.Marshal(details)
	if err != nil {
		return nil, err
	}
	return &Event{
		Type:      eventType,
		Timestamp: time.Now(),
		Details:   detailsBytes,
	}, nil
}

// LogEvent serializes an event to JSON for logging or further processing.
func LogEvent(e *Event) (string, error) {
	eventBytes, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	return string(eventBytes), nil
}
