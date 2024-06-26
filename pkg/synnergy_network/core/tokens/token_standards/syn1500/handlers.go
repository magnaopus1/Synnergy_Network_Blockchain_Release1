package syn1500

import (
	"errors"
	"fmt"
	"log"
)

// TokenHandler manages operations on reputation tokens.
type TokenHandler struct {
	storage *TokenStorage
}

// NewTokenHandler creates a new handler with a reference to the storage backend.
func NewTokenHandler(storage *TokenStorage) *TokenHandler {
	return &TokenHandler{
		storage: storage,
	}
}

// CreateToken handles the creation of new reputation tokens.
func (h *TokenHandler) CreateToken(owner string, initialScore int, trustLevel string) (*ReputationToken, error) {
	tokenID := GenerateTokenID(owner)
	token := NewReputationToken(tokenID, owner, initialScore, trustLevel)
	err := h.storage.SaveToken(token)
	if err != nil {
		log.Printf("Error creating token: %v", err)
		return nil, fmt.Errorf("failed to create token: %w", err)
	}
	log.Printf("Token successfully created with ID %s", token.ID)
	return token, nil
}

// UpdateReputationScore handles updates to the reputation score of a token.
func (h *TokenHandler) UpdateReputationScore(tokenID string, newScore int) error {
	token, _, err := h.storage.GetTokenDetails(tokenID)
	if err != nil {
		log.Printf("Error retrieving token: %v", err)
		return fmt.Errorf("failed to retrieve token: %w", err)
	}

	token.UpdateReputation(newScore)
	err = h.storage.UpdateToken(token)
	if err != nil {
		log.Printf("Error updating token: %v", err)
		return fmt.Errorf("failed to update token: %w", err)
	}
	log.Printf("Token %s reputation score updated to %d", tokenID, newScore)
	return nil
}

// TransferTokenOwnership handles the ownership transfer of a token.
func (h *TokenHandler) TransferTokenOwnership(tokenID, newOwner string) error {
	token, _, err := h.storage.GetTokenDetails(tokenID)
	if err != nil {
		log.Printf("Error retrieving token: %v", err)
		return fmt.Errorf("failed to retrieve token: %w", err)
	}

	token.TransferOwnership(newOwner)
	err = h.storage.UpdateToken(token)
	if err != nil {
		log.Printf("Error updating token ownership: %v", err)
		return fmt.Errorf("failed to update token ownership: %w", err)
	}
	log.Printf("Token %s ownership transferred to %s", tokenID, newOwner)
	return nil
}

// GetTokenDetails provides detailed information about a specific token.
func (h *TokenHandler) GetTokenDetails(tokenID string) (map[string]interface{}, error) {
	token, events, err := h.storage.GetTokenDetails(tokenID)
	if err != nil {
		log.Printf("Error retrieving token details: %v", err)
		return nil, fmt.Errorf("failed to retrieve token details: %w", err)
	}

	details := token.GetDetails()
	details["Events"] = events
	log.Printf("Retrieved details for token %s", tokenID)
	return details, nil
}

// Example usage demonstrates how the handlers can be used within the application.
func ExampleUsage(handler *TokenHandler) {
	// Creating a token
	token, err := handler.CreateToken("user123", 50, "Medium")
	if err != nil {
		log.Printf("Failed to create token: %v", err)
		return
	}

	// Updating reputation score
	err = handler.UpdateReputationScore(token.ID, 75)
	if err != nil {
		log.Printf("Failed to update reputation score: %v", err)
		return
	}

	// Transferring ownership
	err = handler.TransferTokenOwnership(token.ID, "user456")
	if err != nil {
		log.Printf("Failed to transfer ownership: %v", err)
		return
	}

	// Getting token details
	details, err := handler.GetTokenDetails(token.ID)
	if err != nil {
		log.Printf("Failed to get token details: %v", err)
		return
	}

	fmt.Println("Token Details:", details)
}

