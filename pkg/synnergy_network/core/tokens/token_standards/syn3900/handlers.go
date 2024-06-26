package syn3900

import (
    "log"
    "time"
)

// BenefitTokenHandler manages operations related to benefit tokens.
type BenefitTokenHandler struct {
    Registry *BenefitRegistry
    Store    DataStore
}

// NewBenefitTokenHandler initializes a new handler with a given registry and storage system.
func NewBenefitTokenHandler(registry *BenefitRegistry, store DataStore) *BenefitTokenHandler {
    return &BenefitTokenHandler{
        Registry: registry,
        Store:    store,
    }
}

// CreateBenefitToken creates a new benefit token and saves it to the registry.
func (h *BenefitTokenHandler) CreateBenefitToken(benefitType, recipient string, amount float64, validFrom, validUntil time.Time, conditions []string) (string, error) {
    tokenID, err := h.Registry.CreateBenefitToken(benefitType, recipient, amount, validFrom, validUntil, conditions)
    if err != nil {
        log.Printf("Error creating benefit token: %v", err)
        return "", err
    }

    // Save changes to storage
    if err := h.Store.SaveBenefitRegistry(h.Registry); err != nil {
        log.Printf("Failed to save benefit registry after creating token: %v", err)
        return "", err
    }

    log.Printf("Benefit token successfully created: %s", tokenID)
    return tokenID, nil
}

// UpdateBenefitStatus changes the status of a benefit token.
func (h *BenefitTokenHandler) UpdateBenefitStatus(tokenID, status string) error {
    if err := h.Registry.ChangeBenefitStatus(tokenID, status); err != nil {
        log.Printf("Error changing status of benefit token: %v", err)
        return err
    }

    // Save changes to storage
    if err := h.Store.SaveBenefitRegistry(h.Registry); err != nil {
        log.Printf("Failed to save benefit registry after updating token status: %v", err)
        return err
    }

    log.Printf("Benefit status updated successfully for token: %s", tokenID)
    return nil
}

// GetBenefitDetails retrieves and returns the details of a specific benefit token.
func (h *BenefitTokenHandler) GetBenefitDetails(tokenID string) (*BenefitToken, error) {
    benefitToken, err := h.Registry.GetBenefitDetails(tokenID)
    if err != nil {
        log.Printf("Error retrieving benefit token details: %v", err)
        return nil, err
    }

    return benefitToken, nil
}
