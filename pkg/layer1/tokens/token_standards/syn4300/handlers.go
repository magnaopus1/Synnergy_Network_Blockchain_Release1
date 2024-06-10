package syn4300

import (
    "fmt"
    "log"
    "time"
)

// EnergyTokenHandler manages operations related to energy tokens.
type EnergyTokenHandler struct {
    Registry *EnergyRegistry
    Store    DataStore
}

// NewEnergyTokenHandler initializes a new handler with a given registry and storage system.
func NewEnergyTokenHandler(registry *EnergyRegistry, store DataStore) *EnergyTokenHandler {
    return &EnergyTokenHandler{
        Registry: registry,
        Store:    store,
    }
}

// CreateEnergyToken creates a new energy token and saves it to the registry.
func (h *EnergyTokenHandler) CreateEnergyToken(assetType, owner, location, certification string, quantity float64, validUntil time.Time) (string, error) {
    tokenID, err := h.Registry.CreateEnergyToken(assetType, owner, quantity, validUntil)
    if err != nil {
        log.Printf("Error creating energy token: %v", err)
        return "", err
    }

    // Save changes to storage
    if err := h.Store.SaveEnergyRegistry(h.Registry); err != nil {
        log.Printf("Failed to save energy registry after creating token: %v", err)
        return "", err
    }

    log.Printf("Energy token successfully created: %s", tokenID)
    return tokenID, nil
}

// UpdateEnergyTokenStatus updates the status of an energy token (e.g., traded, retired).
func (h *EnergyTokenHandler) UpdateEnergyTokenStatus(tokenID, status string) error {
    if err := h.Registry.UpdateEnergyTokenStatus(tokenID, status); err != nil {
        log.Printf("Error updating energy token status: %v", err)
        return err
    }

    // Save changes to storage
    if err := h.Store.SaveEnergyRegistry(h.Registry); err != nil {
        log.Printf("Failed to save energy registry after updating token status: %v", err)
        return err
    }

    log.Printf("Energy token status updated successfully for token: %s", tokenID)
    return nil
}

// GetEnergyTokenDetails retrieves and returns the details of a specific energy token.
func (h *EnergyTokenHandler) GetEnergyTokenDetails(tokenID string) (*EnergyToken, error) {
    energyToken, err := h.Registry.GetEnergyTokenDetails(tokenID)
    if err != nil {
        log.Printf("Error retrieving energy token details: %v", err)
        return nil, err
    }

    return energyToken, nil
}
