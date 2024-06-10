package syn3800

import (
    "log"
    "time"
)

// GrantTokenHandler manages operations related to grant tokens.
type GrantTokenHandler struct {
    Registry *GrantRegistry
    Store    DataStore
}

// NewGrantTokenHandler initializes a new handler with a given registry and storage system.
func NewGrantTokenHandler(registry *GrantRegistry, store DataStore) *GrantTokenHandler {
    return &GrantTokenHandler{
        Registry: registry,
        Store:    store,
    }
}

// CreateGrantToken creates a new grant token and saves it to the registry.
func (h *GrantTokenHandler) CreateGrantToken(grantName, beneficiary, purpose string, amount float64, expiryDate time.Time, conditions []string) (string, error) {
    tokenID, err := h.Registry.CreateGrantToken(grantName, beneficiary, purpose, amount, expiryDate, conditions)
    if err != nil {
        log.Printf("Error creating grant token: %v", err)
        return "", err
    }

    // Save changes to storage
    if err := h.Store.SaveGrantRegistry(h.Registry); err != nil {
        log.Printf("Failed to save grant registry after creating token: %v", err)
        return "", err
    }

    log.Printf("Grant token successfully created: %s", tokenID)
    return tokenID, nil
}

// DisburseFunds disburses funds from a specific grant token.
func (h *GrantTokenHandler) DisburseFunds(tokenID string, amount float64, metConditions []string) error {
    if err := h.Registry.DisburseFunds(tokenID, amount, metConditions); err != nil {
        log.Printf("Error disbursing funds: %v", err)
        return err
    }

    // Save changes to storage
    if err := h.Store.SaveGrantRegistry(h.Registry); err != nil {
        log.Printf("Failed to save grant registry after disbursing funds: %v", err)
        return err
    }

    log.Println("Funds successfully disbursed")
    return nil
}

// GetGrantDetails retrieves and returns the details of a specific grant token.
func (h *GrantTokenHandler) GetGrantDetails(tokenID string) (*GrantToken, error) {
    grantToken, err := h.Registry.GetGrantDetails(tokenID)
    if err != nil {
        log.Printf("Error retrieving grant token details: %v", err)
        return nil, err
    }

    return grantToken, nil
}
