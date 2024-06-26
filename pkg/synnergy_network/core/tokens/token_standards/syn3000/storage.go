package syn3000

import (
    "sync"
    "errors"
    "fmt"
)

// StorageInterface defines the necessary methods that any storage system must implement for managing rental tokens.
type StorageInterface interface {
    SaveToken(token RentalToken) error
    UpdateToken(tokenID string, updatedToken RentalToken) error
    DeleteToken(tokenID string) error
    FindToken(tokenID string) (RentalToken, error)
    ListAllTokens() ([]RentalToken, error)
    ListTokensByCriteria(criteria map[string]string) ([]RentalToken, error)
}

// InMemoryStorage provides a thread-safe in-memory storage for rental tokens.
type InMemoryStorage struct {
    tokens map[string]RentalToken
    lock   sync.RWMutex
}

// NewInMemoryStorage initializes a new instance of in-memory storage.
func NewInMemoryStorage() *InMemoryStorage {
    return &InMemoryStorage{
        tokens: make(map[string]RentalToken),
    }
}

// SaveToken saves a new rental token in the storage.
func (s *InMemoryStorage) SaveToken(token RentalToken) error {
    s.lock.Lock()
    defer s.lock.Unlock()

    if _, exists := s.tokens[token.TokenID]; exists {
        return fmt.Errorf("token with ID %s already exists", token.TokenID)
    }

    s.tokens[token.TokenID] = token
    return nil
}

// UpdateToken updates an existing rental token.
func (s *InMemoryStorage) UpdateToken(tokenID string, updatedToken RentalToken) error {
    s.lock.Lock()
    defer s.lock.Unlock()

    if _, exists := s.tokens[tokenID]; !exists {
        return fmt.Errorf("token with ID %s does not exist", tokenID)
    }

    s.tokens[tokenID] = updatedToken
    return nil
}

// DeleteToken removes a token from the storage.
func (s *InMemoryStorage) DeleteToken(tokenID string) error {
    s.lock.Lock()
    defer s.lock.Unlock()

    if _, exists := s.tokens[tokenID]; !exists {
        return fmt.Errorf("token with ID %s not found", tokenID)
    }

    delete(s.tokens, tokenID)
    return nil
}

// FindToken retrieves a token by its ID.
func (s *InMemoryStorage) FindToken(tokenID string) (RentalToken, error) {
    s.lock.RLock()
    defer s.lock.RUnlock()

    token, exists := s.tokens[tokenID]
    if !exists {
        return RentalToken{}, fmt.Errorf("token with ID %s not found", tokenID)
    }
    return token, nil
}

// ListAllTokens returns all tokens stored.
func (s *InMemoryStorage) ListAllTokens() ([]RentalToken, error) {
    s.lock.RLock()
    defer s.lock.RUnlock()

    var tokens []RentalToken
    for _, token := range s.tokens {
        tokens = append(tokens, token)
    }
    return tokens, nil
}

// ListTokensByCriteria lists tokens that meet specific criteria.
func (s *InMemoryStorage) ListTokensByCriteria(criteria map[string]string) ([]RentalToken, error) {
    s.lock.RLock()
    defer s.lock.RUnlock()

    var tokens []RentalToken
    for _, token := range s.tokens {
        match := true
        for key, value := range criteria {
            switch key {
            case "propertyId":
                if token.Property.PropertyID != value {
                    match = false
                }
            case "tenant":
                if token.Tenant != value {
                    match = false
                }
            case "active":
                if (value == "true" && !token.Active) || (value == "false" && token.Active) {
                    match = false
                }
            }
        }
        if match {
            tokens = append(tokens, token)
        }
    }
    if len(tokens) == 0 {
        return nil, errors.New("no tokens found matching criteria")
    }
    return tokens, nil
}

