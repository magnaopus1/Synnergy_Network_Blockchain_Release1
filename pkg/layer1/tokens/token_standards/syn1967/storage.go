package syn1967

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// Storage simulates a storage engine for commodity tokens.
type Storage struct {
	mu     sync.RWMutex
	Tokens map[string]Token
}

// NewStorage initializes and returns a new instance of Storage.
func NewStorage() *Storage {
	return &Storage{
		Tokens: make(map[string]Token),
	}
}

// LoadFromFile loads tokens from a JSON file.
func (s *Storage) LoadFromFile(filename string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("unable to open file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&s.Tokens)
	if err != nil {
		return fmt.Errorf("error decoding tokens: %v", err)
	}

	return nil
}

// SaveToFile saves the tokens to a JSON file.
func (s *Storage) SaveToFile(filename string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("unable to create file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(s.Tokens)
	if err != nil {
		return fmt.Errorf("error encoding tokens: %v", err)
	}

	return nil
}

// AddToken adds a new token to the storage.
func (s *Storage) AddToken(token Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.Tokens[token.TokenID]; exists {
		return errors.New("token already exists")
	}

	s.Tokens[token.TokenID] = token
	return nil
}

// GetToken retrieves a token by its ID.
func (s *Storage) GetToken(tokenID string) (Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	token, exists := s.Tokens[tokenID]
	if !exists {
		return Token{}, fmt.Errorf("token with ID %s not found", tokenID)
	}

	return token, nil
}

// DeleteToken removes a token from the storage.
func (s *Storage) DeleteToken(tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.Tokens[tokenID]; !exists {
		return fmt.Errorf("token with ID %s not found", tokenID)
	}

	delete(s.Tokens, tokenID)
	return nil
}

// UpdateToken updates the details of an existing token.
func (s *Storage) UpdateToken(token Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.Tokens[token.TokenID]; !exists {
		return fmt.Errorf("token with ID %s not found", tokenID)
	}

	s.Tokens[token.TokenID] = token
	return nil
}
