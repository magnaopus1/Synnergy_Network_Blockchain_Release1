package syn2200

import (
	"encoding/json"
	"log"
	"time"
)

// Event types for real-time payment token lifecycle
const (
	EventTokenCreated  = "TokenCreated"
	EventTokenTransferred = "TokenTransferred"
	EventTokenRedeemed = "TokenRedeemed"
)

// TokenEvent defines the structure for token-related events
type TokenEvent struct {
	Type      string    `json:"type"`      // Type of the event
	Timestamp time.Time `json:"timestamp"` // Time when the event occurred
	Details   string    `json:"details"`   // Detailed message or data about the event
}

// TokenCreatedEventDetails includes details specific to the token creation event
type TokenCreatedEventDetails struct {
	TokenID string `json:"tokenId"`
	Owner   string `json:"owner"`
	Amount  float64 `json:"amount"`
}

// TokenTransferredEventDetails includes details specific to the token transfer event
type TokenTransferredEventDetails struct {
	TokenID  string `json:"tokenId"`
	From     string `json:"from"`
	To       string `json:"to"`
	Amount   float64 `json:"amount"`
}

// TokenRedeemedEventDetails includes details specific to the token redemption event
type TokenRedeemedEventDetails struct {
	TokenID string `json:"tokenId"`
	Owner   string `json:"owner"`
}

// LogEvent logs any event related to the SYN2200 token standard
func LogEvent(eventType string, details interface{}) {
	event := TokenEvent{
		Type:      eventType,
		Timestamp: time.Now(),
		Details:   encodeEventDetails(details),
	}
	log.Printf("Event Logged: %v", event)
}

// encodeEventDetails converts event details into a JSON string
func encodeEventDetails(details interface{}) string {
	jsonDetails, err := json.Marshal(details)
	if err != nil {
		log.Printf("Error encoding event details: %v", err)
		return "{}"
	}
	return string(jsonDetails)
}

// Example of logging a token creation event
func ExampleLogTokenCreated(tokenID, owner string, amount float64) {
	details := TokenCreatedEventDetails{
		TokenID: tokenID,
		Owner:   owner,
		Amount:  amount,
	}
	LogEvent(EventTokenCreated, details)
}

// Example of logging a token transfer event
func ExampleLogTokenTransferred(tokenID, from, to string, amount float64) {
	details := TokenTransferredEventDetails{
		TokenID:  tokenID,
		From:     from,
		To:       to,
		Amount:   amount,
	}
	LogEvent(EventTokenTransferred, details)
}

// Example of logging a token redemption event
func ExampleLogTokenRedeemed(tokenID, owner string) {
	details := TokenRedeemedEventDetails{
		TokenID: tokenID,
		Owner:   owner,
	}
	LogEvent(EventTokenRedeemed, details)
}
