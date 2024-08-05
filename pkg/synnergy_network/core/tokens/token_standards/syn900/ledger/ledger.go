package ledger

import (
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn900/assets"
)

// Ledger represents the ledger for SYN900 tokens
type Ledger struct {
	tokens map[string]*assets.Syn900Token
}

// NewLedger initializes a new Ledger
func NewLedger() *Ledger {
	return &Ledger{
		tokens: make(map[string]*assets.Syn900Token),
	}
}

// AddToken adds a new token to the ledger
func (l *Ledger) AddToken(token *assets.Syn900Token) error {
	if _, exists := l.tokens[token.TokenID]; exists {
		return errors.New("token already exists in the ledger")
	}
	l.tokens[token.TokenID] = token
	return nil
}

// GetToken retrieves a token by its ID
func (l *Ledger) GetToken(tokenID string) (*assets.Syn900Token, error) {
	token, exists := l.tokens[tokenID]
	if !exists {
		return nil, errors.New("token not found")
	}
	return token, nil
}

// UpdateToken updates the details of an existing token in the ledger
func (l *Ledger) UpdateToken(tokenID string, updatedToken *assets.Syn900Token) error {
	if _, exists := l.tokens[tokenID]; !exists {
		return errors.New("token not found")
	}
	l.tokens[tokenID] = updatedToken
	return nil
}

// DeleteToken removes a token from the ledger
func (l *Ledger) DeleteToken(tokenID string) error {
	if _, exists := l.tokens[tokenID]; !exists {
		return errors.New("token not found")
	}
	delete(l.tokens, tokenID)
	return nil
}

// TransferToken transfers a token to new owners and logs the event
func (l *Ledger) TransferToken(tokenID string, newOwners []string) ([]*assets.Syn900Token, error) {
	token, exists := l.tokens[tokenID]
	if !exists {
		return nil, errors.New("token not found")
	}
	newTokens := token.TransferToken(newOwners)
	for _, newToken := range newTokens {
		l.tokens[newToken.TokenID] = newToken
	}
	return newTokens, nil
}

// LogEvent logs an event related to a token
func (l *Ledger) LogEvent(tokenID, eventType, description, actor string) error {
	token, exists := l.tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}
	eventLogger := assets.NewEventLogger()
	eventLogger.LogEvent(eventType, description, actor)
	// Save the logged events to the token's verification log
	token.VerificationLog = append(token.VerificationLog, assets.VerificationRecord{
		Timestamp:   time.Now(),
		EventType:   eventType,
		Description: description,
		Actor:       actor,
	})
	return nil
}

// GetAuditTrail retrieves the audit trail for a token
func (l *Ledger) GetAuditTrail(tokenID string) ([]assets.AuditRecord, error) {
	token, exists := l.tokens[tokenID]
	if !exists {
		return nil, errors.New("token not found")
	}
	return token.AuditTrail, nil
}

// GetComplianceRecords retrieves the compliance records for a token
func (l *Ledger) GetComplianceRecords(tokenID string) ([]assets.ComplianceRecord, error) {
	token, exists := l.tokens[tokenID]
	if !exists {
		return nil, errors.New("token not found")
	}
	return token.ComplianceRecords, nil
}
