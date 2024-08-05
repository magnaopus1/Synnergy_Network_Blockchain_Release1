// syn5000.go

package syn5000

import (
	"time"
	"errors"
	"github.com/synnergy_network/core/assets"
	"github.com/synnergy_network/core/betting_management"
	"github.com/synnergy_network/core/compliance"
	"github.com/synnergy_network/core/ledger"
	"github.com/synnergy_network/core/security"
	"github.com/synnergy_network/core/transactions"
)

// SYN5000Token represents a gambling token in the SYN5000 standard
type SYN5000Token struct {
	TokenID       string
	GameType      string
	Amount        float64
	Owner         string
	IssuedDate    time.Time
	ExpiryDate    time.Time
	ActiveStatus  bool
	TransactionHistory []transactions.TransactionRecord
	SecureHash    string
}

// SYN5000 represents the core structure for managing SYN5000 tokens
type SYN5000 struct {
	ledger          *ledger.Ledger
	securityManager *security.SecurityManager
	compliance      *compliance.ComplianceManager
	bettingManager  *betting_management.BettingManager
}

// NewSYN5000 creates a new SYN5000 instance
func NewSYN5000(ledger *ledger.Ledger, securityManager *security.SecurityManager, compliance *compliance.ComplianceManager, bettingManager *betting_management.BettingManager) *SYN5000 {
	return &SYN5000{
		ledger:          ledger,
		securityManager: securityManager,
		compliance:      compliance,
		bettingManager:  bettingManager,
	}
}

// IssueToken issues a new SYN5000 token
func (s *SYN5000) IssueToken(tokenID, gameType string, amount float64, owner string, expiryDate time.Time) (*SYN5000Token, error) {
	issuedDate := time.Now()
	token := &SYN5000Token{
		TokenID:       tokenID,
		GameType:      gameType,
		Amount:        amount,
		Owner:         owner,
		IssuedDate:    issuedDate,
		ExpiryDate:    expiryDate,
		ActiveStatus:  true,
		TransactionHistory: []transactions.TransactionRecord{},
	}
	
	// Generate secure hash for the token
	hash, err := s.securityManager.GenerateSecureHash(token)
	if err != nil {
		return nil, err
	}
	token.SecureHash = hash

	// Add token to ledger
	if err := s.ledger.AddToken(token); err != nil {
		return nil, err
	}

	return token, nil
}

// TransferToken handles the transfer of a SYN5000 token from one owner to another
func (s *SYN5000) TransferToken(tokenID, from, to string) error {
	token, err := s.ledger.GetToken(tokenID)
	if err != nil {
		return err
	}

	if token.Owner != from {
		return errors.New("transfer failed: the sender does not own the token")
	}

	// Compliance check for the transfer
	if err := s.compliance.ValidateTransfer(from, to); err != nil {
		return err
	}

	// Record the transfer in the transaction history
	transaction := transactions.TransactionRecord{
		TransactionID:  s.securityManager.GenerateTransactionID(),
		From:           from,
		To:             to,
		Amount:         token.Amount,
		Timestamp:      time.Now(),
	}
	token.TransactionHistory = append(token.TransactionHistory, transaction)

	// Update the owner in the token record
	token.Owner = to

	// Update the token in the ledger
	if err := s.ledger.UpdateToken(token); err != nil {
		return err
	}

	return nil
}

// ValidateToken ensures the token's data integrity and compliance
func (s *SYN5000) ValidateToken(tokenID string) (bool, error) {
	token, err := s.ledger.GetToken(tokenID)
	if err != nil {
		return false, err
	}

	// Validate the secure hash
	if !s.securityManager.ValidateSecureHash(token, token.SecureHash) {
		return false, errors.New("validation failed: token data integrity compromised")
	}

	// Check token's active status and expiry date
	if !token.ActiveStatus || token.ExpiryDate.Before(time.Now()) {
		return false, errors.New("validation failed: token is inactive or expired")
	}

	// Compliance check for token validity
	if err := s.compliance.ValidateToken(token); err != nil {
		return false, err
	}

	return true, nil
}

// DeactivateToken deactivates a token, making it non-transferable and invalid for future use
func (s *SYN5000) DeactivateToken(tokenID string) error {
	token, err := s.ledger.GetToken(tokenID)
	if err != nil {
		return err
	}

	token.ActiveStatus = false

	if err := s.ledger.UpdateToken(token); err != nil {
		return err
	}

	return nil
}

// RevokeToken revokes a token, typically used in cases of fraud or regulatory non-compliance
func (s *SYN5000) RevokeToken(tokenID, reason string) error {
	token, err := s.ledger.GetToken(tokenID)
	if err != nil {
		return err
	}

	// Securely log the revocation reason
	revocationDetails := fmt.Sprintf("Revocation reason: %s", reason)
	encryptedDetails, err := s.securityManager.Encrypt(revocationDetails)
	if err != nil {
		return err
	}
	token.SecureHash = encryptedDetails

	// Mark token as revoked in the ledger
	token.ActiveStatus = false
	if err := s.ledger.UpdateToken(token); err != nil {
		return err
	}

	return nil
}
