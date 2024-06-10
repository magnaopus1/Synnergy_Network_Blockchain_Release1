package syn5000

import (
    "fmt"
    "log"
    "time"
)

// GamblingTokenHandler handles the operations related to gambling tokens.
type GamblingTokenHandler struct {
    Registry *GamblingRegistry
    Store    DataStore
}

// NewGamblingTokenHandler creates a new handler for gambling tokens.
func NewGamblingTokenHandler(registry *GamblingRegistry, store DataStore) *GamblingTokenHandler {
    return &GamblingTokenHandler{
        Registry: registry,
        Store:    store,
    }
}

// CreateToken creates a new gambling token and persists the update to storage.
func (h *GamblingTokenHandler) CreateToken(gameType string, amount float64, owner string, expiryDate time.Time) (string, error) {
    tokenID, err := h.Registry.CreateToken(gameType, amount, owner, expiryDate)
    if err != nil {
        log.Printf("Error creating token: %v", err)
        return "", err
    }

    if err := h.Store.SaveRegistry(h.Registry); err != nil {
        log.Printf("Failed to save registry after creating token: %v", err)
        return "", err
    }

    return tokenID, nil
}

// ActivateToken changes the active status of a token.
func (h *GamblingTokenHandler) ActivateToken(tokenID string, active bool) error {
    if err := h.Registry.UpdateTokenStatus(tokenID, active); err != nil {
        log.Printf("Error updating token status: %v", err)
        return err
    }

    if err := h.Store.SaveRegistry(h.Registry); err != nil {
        log.Printf("Failed to save registry after updating token status: %v", err)
        return err
    }

    return nil
}

// TransferToken transfers ownership of a gambling token to a new owner.
func (h *GamblingTokenHandler) TransferToken(tokenID, newOwner string) error {
    token, err := h.Registry.GetTokenDetails(tokenID)
    if err != nil {
        log.Printf("Error retrieving token: %v", err)
        return err
    }

    // Log this transfer as a transaction
    description := fmt.Sprintf("Transferred from %s to %s", token.Owner, newOwner)
    if err := h.Registry.RecordTransaction(tokenID, description, token.Amount); err != nil {
        log.Printf("Error recording transaction: %v", err)
        return err
    }

    token.Owner = newOwner

    if err := h.Store.SaveRegistry(h.Registry); err != nil {
        log.Printf("Failed to save registry after transferring token: %v", err)
        return err
    }

    return nil
}

// GetToken retrieves the details of a specific token.
func (h *GamblingTokenHandler) GetToken(tokenID string) (*GamblingToken, error) {
    token, err := h.Registry.GetTokenDetails(tokenID)
    if err != nil {
        log.Printf("Error retrieving token: %v", err)
        return nil, err
    }

    return token, nil
}
