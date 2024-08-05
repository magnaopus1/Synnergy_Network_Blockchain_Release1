package syn722

import (
	"errors"
	"time"
)

// SYN722Token represents a SYN722 token
type SYN722Token struct {
	ID          string
	Owner       string
	Mode        TokenMode
	Quantity    int
	Metadata    Syn722Metadata
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// TokenMode represents the mode of the token, either fungible or non-fungible
type TokenMode int

const (
	Fungible TokenMode = iota
	NonFungible
)

// SYN722 represents the SYN722 token standard
type SYN722 struct {
	tokens       map[string]*SYN722Token
	events       *EventManager
	permissions  *PermissionManager
	mintLock     sync.Mutex
	burnLock     sync.Mutex
	switchLock   sync.Mutex
}

// NewSYN722 creates a new instance of the SYN722 token standard
func NewSYN722() *SYN722 {
	return &SYN722{
		tokens:      make(map[string]*SYN722Token),
		events:      NewEventManager(),
		permissions: NewPermissionManager(),
	}
}

// MintToken mints a new SYN722 token
func (s *SYN722) MintToken(owner string, mode TokenMode, quantity int, metadata map[string]interface{}) (string, error) {
	s.mintLock.Lock()
	defer s.mintLock.Unlock()

	if mode == Fungible && quantity <= 0 {
		return "", errors.New("quantity must be greater than zero for fungible tokens")
	}
	if mode == NonFungible && quantity != 1 {
		return "", errors.New("quantity must be one for non-fungible tokens")
	}

	tokenID := generateTokenID()
	token := &SYN722Token{
		ID:       tokenID,
		Owner:    owner,
		Mode:     mode,
		Quantity: quantity,
		Metadata: metadata,
	}

	s.tokens[tokenID] = token
	s.events.AddEvent(EventTypeTokenCreated, map[string]interface{}{"tokenID": tokenID, "owner": owner, "mode": mode, "quantity": quantity, "metadata": metadata})

	return tokenID, nil
}

// TransferToken transfers ownership of a SYN722 token
func (s *SYN722) TransferToken(tokenID, newOwner string, quantity int) error {
	s.switchLock.Lock()
	defer s.switchLock.Unlock()

	token, exists := s.tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}

	if token.Mode == Fungible {
		if token.Quantity < quantity {
			return errors.New("insufficient quantity")
		}
		token.Quantity -= quantity

		if token.Quantity == 0 {
			token.Owner = newOwner
		} else {
			newTokenID := generateTokenID()
			newToken := &SYN722Token{
				ID:       newTokenID,
				Owner:    newOwner,
				Mode:     Fungible,
				Quantity: quantity,
				Metadata: token.Metadata,
			}
			s.tokens[newTokenID] = newToken
		}
	} else {
		if quantity != 1 {
			return errors.New("quantity must be one for non-fungible tokens")
		}
		token.Owner = newOwner
	}

	s.events.AddEvent(EventTypeTokenTransferred, map[string]interface{}{"tokenID": tokenID, "newOwner": newOwner, "quantity": quantity})

	return nil
}

// BurnToken burns a SYN722 token, removing it from circulation
func (s *SYN722) BurnToken(tokenID string, quantity int) error {
	s.burnLock.Lock()
	defer s.burnLock.Unlock()

	token, exists := s.tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}

	if token.Mode == Fungible {
		if token.Quantity < quantity {
			return errors.New("insufficient quantity")
		}
		token.Quantity -= quantity
		if token.Quantity == 0 {
			delete(s.tokens, tokenID)
		}
	} else {
		if quantity != 1 {
			return errors.New("quantity must be one for non-fungible tokens")
		}
		delete(s.tokens, tokenID)
	}

	s.events.AddEvent(EventTypeTokenBurned, map[string]interface{}{"tokenID": tokenID, "quantity": quantity})

	return nil
}

// SwitchTokenMode switches the mode of a SYN722 token
func (s *SYN722) SwitchTokenMode(tokenID string, newMode TokenMode, condition string) error {
	s.switchLock.Lock()
	defer s.switchLock.Unlock()

	token, exists := s.tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}

	if token.Mode == newMode {
		return errors.New("token is already in the requested mode")
	}

	if condition == "" {
		return errors.New("conversion condition not met")
	}

	token.Mode = newMode
	s.events.AddEvent(EventTypeTokenModeChanged, map[string]interface{}{"tokenID": tokenID, "newMode": newMode})

	return nil
}

// UpdateTokenMetadata updates the metadata of a SYN722 token
func (s *SYN722) UpdateTokenMetadata(tokenID string, metadata map[string]interface{}) error {
	token, exists := s.tokens[tokenID]
	if !exists {
		return errors.New("token not found")
	}

	token.Metadata = metadata
	s.events.AddEvent(EventTypeMetadataUpdated, map[string]interface{}{"tokenID": tokenID, "metadata": metadata})

	return nil
}

// GetToken retrieves a SYN722 token by its ID
func (s *SYN722) GetToken(tokenID string) (*SYN722Token, error) {
	token, exists := s.tokens[tokenID]
	if !exists {
		return nil, errors.New("token not found")
	}

	return token, nil
}

// GetTokenHistory retrieves the history of events for a specific token
func (s *SYN722) GetTokenHistory(tokenID string) []Event {
	return s.events.GetEventsByType(EventType(tokenID))
}

// generateTokenID generates a unique token ID
func generateTokenID() string {
	return "token-" + time.Now().Format("20060102150405.000")
}
