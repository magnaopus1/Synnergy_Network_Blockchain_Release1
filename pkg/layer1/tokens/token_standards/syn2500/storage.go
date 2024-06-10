package syn2500

import (
    "encoding/json"
    "fmt"
    "os"
    "sync"
)

// Storage is responsible for handling the persistent storage of DAO tokens.
type Storage struct {
    file   string
    mutex  sync.RWMutex
    Ledger *DAOLedger
}

// NewStorage initializes a new storage handler with a specified file path for persistence.
func NewStorage(filePath string) *Storage {
    storage := &Storage{
        file:   filePath,
        Ledger: NewDAOLedger(),
    }
    if err := storage.load(); err != nil {
        fmt.Printf("Failed to load data from storage: %s\n", err)
    }
    return storage
}

// Save persists the current state of the ledger to a file.
func (s *Storage) Save() error {
    s.mutex.Lock()
    defer s.mutex.Unlock()

    data, err := json.Marshal(s.Ledger)
    if err != nil {
        return err
    }

    return os.WriteFile(s.file, data, 0644)
}

// load retrieves the ledger's state from a file.
func (s *Storage) load() error {
    s.mutex.Lock()
    defer s.mutex.Unlock()

    data, err := os.ReadFile(s.file)
    if err != nil {
        if os.IsNotExist(err) {
            return nil // It's okay if the file doesn't exist yet
        }
        return err
    }

    if len(data) == 0 {
        return nil // File is empty, no data to load
    }

    return json.Unmarshal(data, s.Ledger)
}

// GetToken fetches a token from storage by its ID.
func (s *Storage) GetToken(tokenID string) (DAOToken, error) {
    s.mutex.RLock()
    defer s.mutex.RUnlock()

    token, exists := s.Ledger.Tokens[tokenID]
    if !exists {
        return DAOToken{}, fmt.Errorf("token with ID %s not found", tokenID)
    }
    return token, nil
}

// GetAllTokens retrieves all tokens for a given DAO.
func (s *Storage) GetAllTokens(daoID string) ([]DAOToken, error) {
    s.mutex.RLock()
    defer s.mutex.RUnlock()

    var tokens []DAOToken
    for _, token := range s.Ledger.Tokens {
        if token.DAOID == daoID {
            tokens = append(tokens, token)
        }
    }
    if len(tokens) == 0 {
        return nil, fmt.Errorf("no tokens found for DAO ID %s", daoID)
    }
    return tokens, nil
}

// AddToken adds a new token to the storage.
func (s *Storage) AddToken(token DAOToken) error {
    s.mutex.Lock()
    defer s.mutex.Unlock()

    if _, exists := s.Ledger.Tokens[token.TokenID]; exists {
        return fmt.Errorf("token with ID %s already exists", token.TokenID)
    }
    s.Ledger.Tokens[token.TokenID] = token
    return s.Save() // Persist changes immediately
}

// UpdateToken modifies an existing token in the storage.
func (s *Storage) UpdateToken(token DAOToken) error {
    s.mutex.Lock()
    defer s.mutex.Unlock()

    _, exists := s.Ledger.Tokens[token.TokenID]
    if !exists {
        return fmt.Errorf("token with ID %s not found", token.TokenID)
    }
    s.Ledger.Tokens[token.TokenID] = token
    return s.Save() // Persist changes immediately
}

// DeleteToken removes a token from the storage.
func (s *Storage) DeleteToken(tokenID string) error {
    s.mutex.Lock()
    defer s.mutex.Unlock()

    _, exists := s.Ledger.Tokens[tokenID]
    if !exists {
        return fmt.Errorf("token with ID %s not found", tokenID)
    }
    delete(s.Ledger.Tokens, tokenID)
    return s.Save() // Persist changes immediately
}
