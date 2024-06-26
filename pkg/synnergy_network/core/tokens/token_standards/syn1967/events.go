package syn1967

import (
	"time"
	"fmt"
)

// CommodityTokenEvent defines the base structure for events related to commodity tokens.
type CommodityTokenEvent struct {
	Type      string    `json:"type"`      // Type of the event: Issued, Transferred, Updated, Deleted
	Timestamp time.Time `json:"timestamp"` // Time when the event occurred
	Details   interface{} `json:"details"` // Specific event details
}

// TokenIssuedDetails includes details specific to when a token is issued.
type TokenIssuedDetails struct {
	TokenID    string  `json:"tokenId"`
	Commodity  string  `json:"commodity"`
	Amount     float64 `json:"amount"`
	IssuedTo   string  `json:"issuedTo"`
}

// TokenTransferredDetails includes details for when a token's ownership is transferred.
type TokenTransferredDetails struct {
	TokenID    string `json:"tokenId"`
	From       string `json:"from"`
	To         string `json:"to"`
	Amount     float64 `json:"amount"`
}

// TokenUpdatedDetails contains details for when a token's data, particularly the market price, is updated.
type TokenUpdatedDetails struct {
	TokenID        string  `json:"tokenId"`
	NewPrice       float64 `json:"newPrice"`
}

// TokenDeletedDetails provides details when a token is deleted from the ledger.
type TokenDeletedDetails struct {
	TokenID string `json:"tokenId"`
}

// EmitTokenIssued emits an event when a new token is issued.
func EmitTokenIssued(tokenID, commodity string, amount float64, issuedTo string) {
	event := CommodityTokenEvent{
		Type:      "Issued",
		Timestamp: time.Now(),
		Details: TokenIssuedDetails{
			TokenID:    tokenID,
			Commodity:  commodity,
			Amount:     amount,
			IssuedTo:   issuedTo,
		},
	}
	// Normally you would send this to an event handling system or log it
	logEvent(event)
}

// EmitTokenTransferred emits an event when a token is transferred from one owner to another.
func EmitTokenTransferred(tokenID, from, to string, amount float64) {
	event := CommodityTokenEvent{
		Type:      "Transferred",
		Timestamp: time.Now(),
		Details: TokenTransferredDetails{
			TokenID: tokenID,
			From:    from,
			To:      to,
			Amount:  amount,
		},
	}
	logEvent(event)
}

// EmitTokenUpdated emits an event when a token's market price is updated.
func EmitTokenUpdated(tokenID string, newPrice float64) {
	event := CommodityTokenEvent{
		Type:      "Updated",
		Timestamp: time.Now(),
		Details: TokenUpdatedDetails{
			TokenID:  tokenID,
			NewPrice: newPrice,
		},
	}
	logEvent(event)
}

// EmitTokenDeleted emits an event when a token is deleted.
func EmitTokenDeleted(tokenID string) {
	event := CommodityTokenEvent{
		Type:      "Deleted",
		Timestamp: time.Now(),
		Details: TokenDeletedDetails{
			TokenID: tokenID,
		},
	}
	logEvent(event)
}

// logEvent simulates logging the event to an external system.
func logEvent(event CommodityTokenEvent) {
	// This function would integrate with an actual event bus or logging system.
	// For simulation, we'll just print the event to standard output (or use structured logging in production).
	fmt.Printf("Event Emitted: %+v\n", event)
}
