package syn3400

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/assets"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/events"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/factory"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/integration"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/ledger"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/management"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/smart_contracts"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/speculation"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/storage"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/trading"
	"github.com/synnergy_network_blockchain/pkg/synnergy_network/core/tokens/token_standards/syn3400/transactions"
)

// Syn3400Token represents the SYN3400 Forex Pair Token standard
type Syn3400Token struct {
	TokenID        string
	ForexPair      assets.ForexPair
	Owner          string
	PositionSize   float64
	OpenRate       float64
	LongShort      string
	OpenedDate     time.Time
	LastUpdated    time.Time
	TransactionIDs []string
}

// NewSyn3400Token creates a new Syn3400Token
func NewSyn3400Token(pair assets.ForexPair, owner string, positionSize float64, openRate float64, longShort string) (*Syn3400Token, error) {
	tokenID := generateTokenID(pair, owner)
	now := time.Now()

	return &Syn3400Token{
		TokenID:      tokenID,
		ForexPair:    pair,
		Owner:        owner,
		PositionSize: positionSize,
		OpenRate:     openRate,
		LongShort:    longShort,
		OpenedDate:   now,
		LastUpdated:  now,
	}, nil
}

// generateTokenID generates a unique token ID based on the Forex pair and owner
func generateTokenID(pair assets.ForexPair, owner string) string {
	data := pair.PairID + owner + time.Now().String()
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// UpdatePosition updates the position size and rate of the token
func (token *Syn3400Token) UpdatePosition(newSize float64, newRate float64) error {
	if newSize <= 0 {
		return errors.New("invalid position size")
	}
	token.PositionSize = newSize
	token.OpenRate = newRate
	token.LastUpdated = time.Now()
	return nil
}

// TransferOwnership transfers the ownership of the token
func (token *Syn3400Token) TransferOwnership(newOwner string) {
	token.Owner = newOwner
	token.LastUpdated = time.Now()
}

// AddTransactionID adds a transaction ID to the token's history
func (token *Syn3400Token) AddTransactionID(transactionID string) {
	token.TransactionIDs = append(token.TransactionIDs, transactionID)
	token.LastUpdated = time.Now()
}

// ValidateOwnership checks if a user is the owner of the token
func (token *Syn3400Token) ValidateOwnership(userID string) bool {
	return token.Owner == userID
}

// ForexTokenManager handles operations related to SYN3400 tokens
type ForexTokenManager struct {
	tokens       map[string]*Syn3400Token
	ledger       *ledger.LedgerManager
	eventLogger  *events.EventLogger
	tokenFactory *factory.TokenFactory
}

// NewForexTokenManager initializes a new ForexTokenManager instance
func NewForexTokenManager(ledger *ledger.LedgerManager, eventLogger *events.EventLogger, tokenFactory *factory.TokenFactory) (*ForexTokenManager, error) {
	return &ForexTokenManager{
		tokens:       make(map[string]*Syn3400Token),
		ledger:       ledger,
		eventLogger:  eventLogger,
		tokenFactory: tokenFactory,
	}, nil
}

// CreateToken creates a new SYN3400 token
func (manager *ForexTokenManager) CreateToken(pair assets.ForexPair, owner string, positionSize float64, openRate float64, longShort string) (*Syn3400Token, error) {
	token, err := NewSyn3400Token(pair, owner, positionSize, openRate, longShort)
	if err != nil {
		return nil, err
	}
	manager.tokens[token.TokenID] = token
	manager.ledger.AddTokenRecord(token.TokenID, token)
	manager.eventLogger.LogEvent(events.Event{
		Type:      "TokenCreation",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"tokenID":     token.TokenID,
			"owner":       owner,
			"positionSize": positionSize,
			"openRate":    openRate,
			"longShort":   longShort,
		},
	})
	return token, nil
}

// GetToken retrieves a token by its ID
func (manager *ForexTokenManager) GetToken(tokenID string) (*Syn3400Token, error) {
	token, exists := manager.tokens[tokenID]
	if !exists {
		return nil, errors.New("token not found")
	}
	return token, nil
}

// TransferToken transfers ownership of a token
func (manager *ForexTokenManager) TransferToken(tokenID string, newOwner string) error {
	token, err := manager.GetToken(tokenID)
	if err != nil {
		return err
	}
	token.TransferOwnership(newOwner)
	manager.ledger.UpdateTokenRecord(token.TokenID, token)
	manager.eventLogger.LogEvent(events.Event{
		Type:      "TokenTransfer",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"tokenID":  token.TokenID,
			"newOwner": newOwner,
		},
	})
	return nil
}

// UpdateTokenPosition updates the position size and rate of a token
func (manager *ForexTokenManager) UpdateTokenPosition(tokenID string, newSize float64, newRate float64) error {
	token, err := manager.GetToken(tokenID)
	if err != nil {
		return err
	}
	err = token.UpdatePosition(newSize, newRate)
	if err != nil {
		return err
	}
	manager.ledger.UpdateTokenRecord(token.TokenID, token)
	manager.eventLogger.LogEvent(events.Event{
		Type:      "TokenPositionUpdate",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"tokenID":  token.TokenID,
			"newSize":  newSize,
			"newRate":  newRate,
		},
	})
	return nil
}

// AddTransactionIDToToken adds a transaction ID to the token's history
func (manager *ForexTokenManager) AddTransactionIDToToken(tokenID string, transactionID string) error {
	token, err := manager.GetToken(tokenID)
	if err != nil {
		return err
	}
	token.AddTransactionID(transactionID)
	manager.ledger.UpdateTokenRecord(token.TokenID, token)
	manager.eventLogger.LogEvent(events.Event{
		Type:      "TransactionIDAdded",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"tokenID":       token.TokenID,
			"transactionID": transactionID,
		},
	})
	return nil
}

// ValidateTokenOwnership validates the ownership of a token
func (manager *ForexTokenManager) ValidateTokenOwnership(tokenID string, userID string) (bool, error) {
	token, err := manager.GetToken(tokenID)
	if err != nil {
		return false, err
	}
	return token.ValidateOwnership(userID), nil
}
