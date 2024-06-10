package syn2100

import (
	"errors"
	"fmt"
	"time"
)

// FinancialDocument represents different types of financial documents that can be tokenized.
type FinancialDocument struct {
	DocumentID   string    `json:"documentId"`   // Unique identifier for the document
	DocumentType string    `json:"documentType"` // Type of document: Invoice, Purchase Order, etc.
	Issuer       string    `json:"issuer"`       // Entity that issued the document
	Recipient    string    `json:"recipient"`    // Entity that received the document
	Amount       float64   `json:"amount"`       // Monetary value of the document
	IssueDate    time.Time `json:"issueDate"`    // Date when the document was issued
	DueDate      time.Time `json:"dueDate"`      // Date by which the document is to be settled
	Description  string    `json:"description"`  // Description of the financial document's purpose and terms
}

// Token represents a tokenized form of financial documents for supply chain financing.
type Token struct {
	TokenID     string            `json:"tokenId"`     // Unique identifier for the token
	FinancialDoc FinancialDocument `json:"financialDoc"` // The financial document associated with this token
	Owner       string            `json:"owner"`       // Current owner of the token
	IsActive    bool              `json:"isActive"`    // Status of the token, active if not redeemed
	AuditTrail  []string          `json:"auditTrail"`  // Historical log of all actions taken on this token
}

// SupplyChainLedger manages the lifecycle and ownership of financial document tokens.
type SupplyChainLedger struct {
	Tokens map[string]Token // Maps Token IDs to their corresponding Tokens
}

// NewSupplyChainLedger creates a new instance of a Supply Chain Ledger.
func NewSupplyChainLedger() *SupplyChainLedger {
	return &SupplyChainLedger{
		Tokens: make(map[string]Token),
	}
}

// IssueToken creates and registers a new token for a financial document.
func (scl *SupplyChainLedger) IssueToken(doc FinancialDocument, owner string) (*Token, error) {
	tokenID := fmt.Sprintf("%s-%s", doc.DocumentType, doc.DocumentID)
	if _, exists := scl.Tokens[tokenID]; exists {
		return nil, fmt.Errorf("token with ID %s already exists", tokenID)
	}

	newToken := Token{
		TokenID:     tokenID,
		FinancialDoc: doc,
		Owner:       owner,
		IsActive:    true,
		AuditTrail:  []string{fmt.Sprintf("Token issued to %s on %v", owner, time.Now())},
	}
	scl.Tokens[tokenID] = newToken
	return &newToken, nil
}

// TransferToken changes the ownership of a token to a new owner.
func (scl *SupplyChainLedger) TransferToken(tokenID, newOwner string) error {
	token, exists := scl.Tokens[tokenID]
	if !exists {
		return errors.New("token does not exist")
	}
	if !token.IsActive {
		return errors.New("token is no longer active")
	}

	token.AuditTrail = append(token.AuditTrail, fmt.Sprintf("Transferred from %s to %s on %v", token.Owner, newOwner, time.Now()))
	token.Owner = newOwner
	scl.Tokens[tokenID] = token
	return nil
}

// GetToken retrieves a token by its ID.
func (scl *SupplyChainLedger) GetToken(tokenID string) (*Token, error) {
	token, exists := scl.Tokens[tokenID]
	if !exists {
		return nil, errors.New("token not found")
	}
	return &token, nil
}

// RedeemToken handles the process of settling or fulfilling the financial obligation associated with a token.
func (scl *SupplyChainLedger) RedeemToken(tokenID string) error {
	token, exists := scl.Tokens[tokenID]
	if !exists {
		return errors.New("token not found for redemption")
	}

	token.IsActive = false
	token.AuditTrail = append(token.AuditTrail, fmt.Sprintf("Token redeemed and deactivated on %v", time.Now()))
	scl.Tokens[tokenID] = token
	return nil
}

// ListTokensByOwner returns all tokens currently owned by a specific entity.
func (scl *SupplyChainLedger) ListTokensByOwner(owner string) ([]Token, error) {
	var ownedTokens []Token
	for _, token := range scl.Tokens {
		if token.Owner == owner && token.IsActive {
			ownedTokens = append(ownedTokens, token)
		}
	}
	if len(ownedTokens) == 0 {
		return nil, fmt.Errorf("no active tokens found for owner %s", owner)
	}
	return ownedTokens, nil
}
