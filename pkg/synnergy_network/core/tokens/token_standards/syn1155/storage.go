package syn1155

import (
	"errors"
	"fmt"
	"log"
	"sync"
)

// TokenStorage manages the storage of tokens.
type TokenStorage struct {
	tokens map[string]*Token // Maps token IDs to token structs
	mutex  sync.RWMutex
}

// NewTokenStorage initializes a new storage system for tokens.
func NewTokenStorage() *TokenStorage {
	return &TokenStorage{
		tokens: make(map[string]*Token),
	}
}

// StoreToken adds a new token to the storage.
func (ts *TokenStorage) StoreToken(token *Token) error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	if _, exists := ts.tokens[token.ID]; exists {
		log.Printf("Attempt to store duplicate token with ID: %s", token.ID)
		return errors.New("token already exists")
	}

	ts.tokens[token.ID] = token
	log.Printf("Token stored with ID: %s", token.ID)
	return nil
}

// RetrieveToken fetches a token from storage by its ID.
func (ts *TokenStorage) RetrieveToken(tokenID string) (*Token, error) {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()

	token, exists := ts.tokens[tokenID]
	if !exists {
		log.Printf("Attempt to retrieve non-existent token with ID: %s", tokenID)
		return nil, fmt.Errorf("token with ID %s does not exist", tokenID)
	}

	log.Printf("Token retrieved with ID: %s", token.ID)
	return token, nil
}

// UpdateToken updates the details of an existing token in storage.
func (ts *TokenStorage) UpdateToken(tokenID string, updateFunc func(*Token) error) error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	token, exists := ts.tokens[tokenID]
	if !exists {
		log.Printf("Attempt to update non-existent token with ID: %s", tokenID)
		return fmt.Errorf("token with ID %s does not exist", tokenID)
	}

	err := updateFunc(token)
	if err != nil {
		log.Printf("Error updating token %s: %v", tokenID, err)
		return err
	}

	log.Printf("Token updated with ID: %s", token.ID)
	return nil
}

// DeleteToken removes a token from storage.
func (ts *TokenStorage) DeleteToken(tokenID string) error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	if _, exists := ts.tokens[tokenID]; !exists {
		log.Printf("Attempt to delete non-existent token with ID: %s", tokenID)
		return fmt.Errorf("token with ID %s does not exist", tokenID)
	}

	delete(ts.tokens, tokenID)
	log.Printf("Token deleted with ID: %s", tokenID)
	return nil
}

// Example of using TokenStorage to manage tokens
func ExampleTokenStorageOperations() {
	storage := NewTokenStorage()
	token := NewToken("token1234", 1000, "owner123")
	_ = storage.StoreToken(token)

	retrievedToken, _ := storage.RetrieveToken("token1234")
	fmt.Println("Retrieved Token:", retrievedToken.ID)

	// Update token logic
	updateFunc := func(t *Token) error {
		t.Owner["newOwner"] = 500 // Example modification
		return nil
	}
	_ = storage.UpdateToken("token1234", updateFunc)

	_ = storage.DeleteToken("token1234")
}
