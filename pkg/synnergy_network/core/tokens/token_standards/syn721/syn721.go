package syn721

import (
	"fmt"
	"sync"
	"time"

	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/assets"
	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/events"
	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/ledger"
	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/security"
	"github.com/synnergy_network_blockchain/core/tokens/token_standards/syn721/transactions"
)

// Syn721Token represents a SYN721 token with full metadata and valuation
type Syn721Token struct {
	ID        string
	Namw	string	
	Owner     string
	Metadata  assets.Metadata
	Valuation assets.Valuation
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Syn721 is the main struct for the SYN721 standard
type Syn721 struct {
	tokens           map[string]Syn721Token
	ledger           *ledger.Ledger
	eventManager     *events.EventManager
	securityManager  *security.SecurityManager
	transferManager  *transactions.TransferManager
	escrowManager    *transactions.EscrowManager
	mutex            sync.Mutex
}

// NewSyn721 initializes a new instance of Syn721
func NewSyn721(ledger *ledger.Ledger, eventManager *events.EventManager, securityManager *security.SecurityManager, transferManager *transactions.TransferManager, escrowManager *transactions.EscrowManager) *Syn721 {
	return &Syn721{
		tokens:          make(map[string]Syn721Token),
		ledger:          ledger,
		eventManager:    eventManager,
		securityManager: securityManager,
		transferManager: transferManager,
		escrowManager:   escrowManager,
	}
}

// MintToken mints a new SYN721 token
func (s *Syn721) MintToken(owner string, metadata assets.Metadata, valuation assets.Valuation) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tokenID, err := s.ledger.GenerateTokenID()
	if err != nil {
		return "", err
	}

	token := Syn721Token{
		ID:        tokenID,
		Owner:     owner,
		Metadata:  metadata,
		Valuation: valuation,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	s.tokens[tokenID] = token
	s.ledger.AddToken(tokenID, owner)
	s.eventManager.LogEvent(events.MintTokenEvent(tokenID, owner, metadata))

	return tokenID, nil
}

// TransferToken transfers a SYN721 token to a new owner
func (s *Syn721) TransferToken(tokenID, newOwner string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	token, exists := s.tokens[tokenID]
	if !exists {
		return fmt.Errorf("token with ID %s not found", tokenID)
	}

	if token.Owner == newOwner {
		return fmt.Errorf("new owner is the same as current owner")
	}

	s.ledger.TransferOwnership(tokenID, newOwner)
	token.Owner = newOwner
	token.UpdatedAt = time.Now()
	s.tokens[tokenID] = token
	s.eventManager.LogEvent(events.TransferTokenEvent(tokenID, token.Owner, newOwner))

	return nil
}

// BurnToken burns a SYN721 token, removing it from circulation
func (s *Syn721) BurnToken(tokenID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	_, exists := s.tokens[tokenID]
	if !exists {
		return fmt.Errorf("token with ID %s not found", tokenID)
	}

	delete(s.tokens, tokenID)
	s.ledger.RemoveToken(tokenID)
	s.eventManager.LogEvent(events.BurnTokenEvent(tokenID))

	return nil
}

// UpdateMetadata updates the metadata of a SYN721 token
func (s *Syn721) UpdateMetadata(tokenID string, newMetadata assets.Metadata) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	token, exists := s.tokens[tokenID]
	if !exists {
		return fmt.Errorf("token with ID %s not found", tokenID)
	}

	oldMetadata := token.Metadata
	token.Metadata = newMetadata
	token.UpdatedAt = time.Now()
	s.tokens[tokenID] = token
	s.ledger.UpdateTokenMetadata(tokenID, newMetadata)
	s.eventManager.LogEvent(events.MetadataUpdateEvent(tokenID, map[string]interface{}{
		"oldMetadata": oldMetadata,
		"newMetadata": newMetadata,
	}))

	return nil
}

// UpdateValuation updates the valuation of a SYN721 token
func (s *Syn721) UpdateValuation(tokenID string, newValuation assets.Valuation) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	token, exists := s.tokens[tokenID]
	if !exists {
		return fmt.Errorf("token with ID %s not found", tokenID)
	}

	oldValuation := token.Valuation
	token.Valuation = newValuation
	token.UpdatedAt = time.Now()
	s.tokens[tokenID] = token
	s.ledger.UpdateTokenValuation(tokenID, newValuation)
	s.eventManager.LogEvent(events.ValuationUpdateEvent(tokenID, map[string]interface{}{
		"oldValuation": oldValuation,
		"newValuation": newValuation,
	}))

	return nil
}

// Approve grants an address permission to manage a SYN721 token
func (s *Syn721) Approve(tokenID, approvedAddress string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	token, exists := s.tokens[tokenID]
	if !exists {
		return fmt.Errorf("token with ID %s not found", tokenID)
	}

	s.securityManager.GrantPermission(token.Owner, approvedAddress, "manage", tokenID)
	s.eventManager.LogEvent(events.ApprovalGrantedEvent(tokenID, approvedAddress))

	return nil
}

// Revoke revokes an address's permission to manage a SYN721 token
func (s *Syn721) Revoke(tokenID, revokedAddress string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	token, exists := s.tokens[tokenID]
	if !exists {
		return fmt.Errorf("token with ID %s not found", tokenID)
	}

	s.securityManager.RevokePermission(token.Owner, revokedAddress, "manage", tokenID)
	s.eventManager.LogEvent(events.ApprovalRevokedEvent(tokenID, revokedAddress))

	return nil
}

// GetToken retrieves a SYN721 token by its ID
func (s *Syn721) GetToken(tokenID string) (Syn721Token, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	token, exists := s.tokens[tokenID]
	if !exists {
		return Syn721Token{}, fmt.Errorf("token with ID %s not found", tokenID)
	}

	return token, nil
}

// GetTokenHistory retrieves the ownership history of a SYN721 token
func (s *Syn721) GetTokenHistory(tokenID string) ([]ledger.OwnershipChange, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	history, err := s.ledger.GetOwnershipHistory(tokenID)
	if err != nil {
		return nil, err
	}

	return history, nil
}

// GetTokenValuationHistory retrieves the valuation history of a SYN721 token
func (s *Syn721) GetTokenValuationHistory(tokenID string) ([]ledger.ValuationChange, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	history, err := s.ledger.GetValuationHistory(tokenID)
	if err != nil {
		return nil, err
	}

	return history, nil
}

// CreateEscrow creates an escrow for a SYN721 token
func (s *Syn721) CreateEscrow(tokenID, buyer string, amount float64) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	token, exists := s.tokens[tokenID]
	if !exists {
		return "", fmt.Errorf("token with ID %s not found", tokenID)
	}

	escrowID, err := s.escrowManager.CreateEscrow(tokenID, token.Owner, buyer, amount)
	if err != nil {
		return "", err
	}

	s.eventManager.LogEvent(events.EscrowCreatedEvent(tokenID, escrowID, amount))
	return escrowID, nil
}

// ReleaseEscrow releases an escrow for a SYN721 token
func (s *Syn721) ReleaseEscrow(escrowID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	escrow, err := s.escrowManager.GetEscrow(escrowID)
	if err != nil {
		return err
	}

	token, exists := s.tokens[escrow.TokenID]
	if !exists {
		return fmt.Errorf("token with ID %s not found", escrow.TokenID)
	}

	if err := s.escrowManager.ReleaseEscrow(escrowID); err != nil {
		return err
	}

	token.Owner = escrow.Buyer
	token.UpdatedAt = time.Now()
	s.tokens[escrow.TokenID] = token
	s.ledger.TransferOwnership(escrow.TokenID, escrow.Buyer)
	s.eventManager.LogEvent(events.EscrowReleasedEvent(escrow.TokenID, escrowID, escrow.Amount))

	return nil
}
