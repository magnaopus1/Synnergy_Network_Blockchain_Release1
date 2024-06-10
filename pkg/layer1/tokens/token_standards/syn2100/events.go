package syn2100

import (
	"encoding/json"
	"fmt"
    "time"
)

// Event types for the SYN2100 token standard
const (
	TokenIssued     = "TokenIssued"
	TokenTransferred = "TokenTransferred"
	TokenRedeemed   = "TokenRedeemed"
)

// Event defines the base structure for events in the SYN2100 standard.
type Event struct {
	Type      string // Type of event
	Details   string // Detailed string or JSON containing event-specific information
	Timestamp int64  // Unix timestamp of the event
}

// TokenIssuedEvent represents the data for a token issuance event.
type TokenIssuedEvent struct {
	TokenID     string  `json:"tokenId"`
	DocumentID  string  `json:"documentId"`
	Issuer      string  `json:"issuer"`
	Recipient   string  `json:"recipient"`
	Amount      float64 `json:"amount"`
	IssueDate   int64   `json:"issueDate"`
}

// TokenTransferredEvent represents the data for a token transfer event.
type TokenTransferredEvent struct {
	TokenID    string `json:"tokenId"`
	From       string `json:"from"`
	To         string `json:"to"`
	TransferDate int64  `json:"transferDate"`
}

// TokenRedeemedEvent represents the data for a token redemption event.
type TokenRedeemedEvent struct {
	TokenID      string `json:"tokenId"`
	Redeemer     string `json:"redeemer"`
	RedemptionDate int64  `json:"redemptionDate"`
}

// NewEvent creates a generic event with a specified type and details.
func NewEvent(eventType string, details interface{}) (*Event, error) {
	detailBytes, err := json.Marshal(details)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal event details: %v", err)
	}

	return &Event{
		Type:      eventType,
		Details:   string(detailBytes),
		Timestamp: CurrentUnixTimestamp(),
	}, nil
}

// CurrentUnixTimestamp returns the current time as a Unix timestamp.
func CurrentUnixTimestamp() int64 {
	return time.Now().Unix()
}

// EmitTokenIssued emits an event when a new token is issued.
func EmitTokenIssued(token Token) {
	eventDetails := TokenIssuedEvent{
		TokenID:    token.TokenID,
		DocumentID: token.FinancialDoc.DocumentID,
		Issuer:     token.FinancialDoc.Issuer,
		Recipient:  token.Owner,
		Amount:     token.FinancialDoc.Amount,
		IssueDate:  CurrentUnixTimestamp(),
	}
	event, _ := NewEvent(TokenIssued, eventDetails)
	fmt.Printf("Event Emitted: %+v\n", event)
}

// EmitTokenTransferred emits an event when a token is transferred.
func EmitTokenTransferred(tokenID, from, to string) {
	eventDetails := TokenTransferredEvent{
		TokenID:    tokenID,
		From:       from,
		To:         to,
		TransferDate: CurrentUnixTimestamp(),
	}
	event, _ := NewEvent(TokenTransferred, eventDetails)
	fmt.Printf("Event Emitted: %+v\n", event)
}

// EmitTokenRedeemed emits an event when a token is redeemed.
func EmitTokenRedeemed(tokenID, redeemer string) {
	eventDetails := TokenRedeemedEvent{
		TokenID:      tokenID,
		Redeemer:     redeemer,
		RedemptionDate: CurrentUnixTimestamp(),
	}
	event, _ := NewEvent(TokenRedeemed, eventDetails)
	fmt.Printf("Event Emitted: %+v\n", event)
}
