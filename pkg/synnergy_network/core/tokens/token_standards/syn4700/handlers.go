package syn4700

import (
    "log"
    "time"
)

// LegalTokenHandler manages operations related to legal tokens.
type LegalTokenHandler struct {
    Registry *LegalRegistry
    Store    DataStore
}

// NewLegalTokenHandler initializes a new handler with a given registry and storage system.
func NewLegalTokenHandler(registry *LegalRegistry, store DataStore) *LegalTokenHandler {
    return &LegalTokenHandler{
        Registry: registry,
        Store:    store,
    }
}

// CreateLegalToken creates a new legal token and saves it to the registry.
func (h *LegalTokenHandler) CreateLegalToken(documentType string, parties []string, contentHash string, expiryDate time.Time, metadata map[string]string) (string, error) {
    tokenID, err := h.Registry.CreateLegalToken(documentType, parties, contentHash, expiryDate, metadata)
    if err != nil {
        log.Printf("Error creating legal token: %v", err)
        return "", err
    }

    // Save changes to storage
    if err := h.Store.SaveLegalRegistry(h.Registry); err != nil {
        log.Printf("Failed to save legal registry after creating token: %v", err)
        return "", err
    }

    log.Printf("Legal token successfully created: %s", tokenID)
    return tokenID, nil
}

// UpdateLegalTokenStatus updates the status of a legal token.
func (h *LegalTokenHandler) UpdateLegalTokenStatus(tokenID, status string) error {
    if err := h.Registry.UpdateLegalTokenStatus(tokenID, status); err != nil {
        log.Printf("Error updating legal token status: %v", err)
        return err
    }

    // Save changes to storage
    if err := h.Store.SaveLegalRegistry(h.Registry); err != nil {
        log.Printf("Failed to save legal registry after updating token status: %v", err)
        return err
    }

    log.Printf("Legal token status updated successfully for token: %s", tokenID)
    return nil
}

// SignLegalToken allows a party to sign the legal token.
func (h *LegalTokenHandler) SignLegalToken(tokenID, party, signature string) error {
    if err := h.Registry.SignLegalToken(tokenID, party, signature); err != nil {
        log.Printf("Error signing legal token: %v", err)
        return err
    }

    // Save changes to storage
    if err := h.Store.SaveLegalRegistry(h.Registry); err != nil {
        log.Printf("Failed to save legal registry after signing token: %v", err)
        return err
    }

    log.Printf("Legal token signed successfully by %s: %s", party, tokenID)
    return nil
}

// GetLegalTokenDetails retrieves and returns the details of a specific legal token.
func (h *LegalTokenHandler) GetLegalTokenDetails(tokenID string) (*LegalToken, error) {
    legalToken, err := h.Registry.GetLegalTokenDetails(tokenID)
    if err != nil {
        log.Printf("Error retrieving legal token details: %v", err)
        return nil, err
    }

    return legalToken, nil
}
