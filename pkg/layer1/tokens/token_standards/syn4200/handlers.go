package syn4200

import (
    "log"
    "time"
)

// CharityTokenHandler manages operations related to charity tokens.
type CharityTokenHandler struct {
    Registry *CharityRegistry
    Store    DataStore
}

// NewCharityTokenHandler initializes a new handler with a given registry and storage system.
func NewCharityTokenHandler(registry *CharityRegistry, store DataStore) *CharityTokenHandler {
    return &CharityTokenHandler{
        Registry: registry,
        Store:    store,
    }
}

// CreateCharityToken creates a new charity token and saves it to the registry.
func (h *CharityTokenHandler) CreateCharityToken(campaignName, donor string, amount float64, purpose string, expiryDate time.Time, traceable bool) (string, error) {
    tokenID, err := h.Registry.CreateCharityToken(campaignName, donor, amount, purpose, expiryDate, traceable)
    if err != nil {
        log.Printf("Error creating charity token: %v", err)
        return "", err
    }

    // Save changes to storage
    if err := h.Store.SaveCharityRegistry(h.Registry); err != nil {
        log.Printf("Failed to save charity registry after creating token: %v", err)
        return "", err
    }

    log.Printf("Charity token successfully created: %s", tokenID)
    return tokenID, nil
}

// UpdateCharityTokenStatus updates the status of a charity token.
func (h *CharityTokenHandler) UpdateCharityTokenStatus(tokenID, status string) error {
    if err := h.Registry.UpdateCharityTokenStatus(tokenID, status); err != nil {
        log.Printf("Error updating charity token status: %v", err)
        return err
    }

    // Save changes to storage
    if err := h.Store.SaveCharityRegistry(h.Registry); err != nil {
        log.Printf("Failed to save charity registry after updating token status: %v", err)
        return err
    }

    log.Printf("Charity token status updated successfully for token: %s", tokenID)
    return nil
}

// GetCharityTokenDetails retrieves and returns the details of a specific charity token.
func (h *CharityTokenHandler) GetCharityTokenDetails(tokenID string) (*CharityToken, error) {
    charityToken, err := h.Registry.GetCharityTokenDetails(tokenID)
    if err != nil {
        log.Printf("Error retrieving charity token details: %v", err)
        return nil, err
    }

    return charityToken, nil
}
