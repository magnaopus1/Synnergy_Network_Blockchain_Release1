package syn2200

import (
	"fmt"
	"time"
)

// PaymentToken represents the structure of a real-time payment token.
type PaymentToken struct {
	TokenID     string    `json:"tokenId"`     // Unique identifier for the token
	Currency    string    `json:"currency"`    // Currency code (ISO 4217)
	Amount      float64   `json:"amount"`      // Amount of money
	Sender      string    `json:"sender"`      // Sender's blockchain address
	Recipient   string    `json:"recipient"`   // Recipient's blockchain address
	CreationTime time.Time `json:"creationTime"` // Time when the token was created
	Executed    bool      `json:"executed"`    // Status to mark if the payment has been processed
	ExecutionTime time.Time `json:"executionTime"` // Time when the payment was executed
}

// PaymentLedger stores all the payment tokens and manages their life cycle.
type PaymentLedger struct {
	Tokens map[string]*PaymentToken // Maps Token IDs to PaymentTokens
}

// NewPaymentLedger initializes a new Payment Ledger.
func NewPaymentLedger() *PaymentLedger {
	return &PaymentLedger{
		Tokens: make(map[string]*PaymentToken),
	}
}

// IssueToken issues a new payment token to facilitate a transaction.
func (pl *PaymentLedger) IssueToken(token PaymentToken) error {
	if _, exists := pl.Tokens[token.TokenID]; exists {
		return fmt.Errorf("payment token with ID %s already exists", token.TokenID)
	}
	token.CreationTime = time.Now()
	token.Executed = false
	pl.Tokens[token.TokenID] = &token
	return nil
}

// ExecuteTransaction marks a token as executed, indicating that the payment has been processed.
func (pl *PaymentLedger) ExecuteTransaction(tokenID string) error {
	token, exists := pl.Tokens[tokenID]
	if !exists {
		return fmt.Errorf("no payment token found with ID %s", tokenID)
	}
	if token.Executed {
		return fmt.Errorf("payment token %s has already been executed", tokenID)
	}
	token.Executed = true
	token.ExecutionTime = time.Now()
	return nil
}

// GetToken retrieves a specific payment token by ID.
func (pl *PaymentLedger) GetToken(tokenID string) (*PaymentToken, error) {
	token, exists := pl.Tokens[tokenID]
	if !exists {
		return nil, fmt.Errorf("payment token with ID %s not found", tokenID)
	}
	return token, nil
}

// ListTransactionsBySender retrieves all tokens issued by a specific sender.
func (pl *PaymentLedger) ListTransactionsBySender(sender string) ([]*PaymentToken, error) {
	var tokens []*PaymentToken
	for _, token := range pl.Tokens {
		if token.Sender == sender {
			tokens = append(tokens, token)
		}
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("no transactions found for sender %s", sender)
	}
	return tokens, nil
}

// ListTransactionsByRecipient retrieves all tokens that have a specific recipient.
func (pl *PaymentLedger) ListTransactionsByRecipient(recipient string) ([]*PaymentToken, error) {
	var tokens []*PaymentToken
	for _, token := range pl.Tokens {
		if token.Recipient == recipient {
			tokens = append(tokens, token)
		}
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("no transactions found for recipient %s", recipient)
	}
	return tokens, nil
}
