package syn3400

import (
    "fmt"
    "log"
)

// ForexHandler provides high-level operations for managing forex pairs and tokens.
type ForexHandler struct {
    Registry *ForexRegistry
    Store    DataStore
}

// NewForexHandler initializes a new ForexHandler with a given registry and storage backend.
func NewForexHandler(registry *ForexRegistry, store DataStore) *ForexHandler {
    return &ForexHandler{
        Registry: registry,
        Store:    store,
    }
}

// AddForexPair creates a new forex pair and persists it.
func (h *ForexHandler) AddForexPair(pairId, baseCurrency, quoteCurrency string, initialRate float64) error {
    err := h.Registry.AddForexPair(pairId, baseCurrency, quoteCurrency, initialRate)
    if err != nil {
        log.Printf("Error adding forex pair: %v", err)
        return err
    }

    // Persist changes
    if err = h.Store.SaveForexRegistry(h.Registry); err != nil {
        log.Printf("Failed to save forex registry after adding pair: %v", err)
        return err
    }
    log.Printf("Forex pair added successfully: %s", pairId)
    return nil
}

// OpenPosition opens a new trading position on a specified forex pair.
func (h *ForexHandler) OpenPosition(pairId, holder string, size float64, isLong bool, openRate float64) (string, error) {
    tokenID, err := h.Registry.OpenPosition(pairId, holder, size, isLong, openRate)
    if err != nil {
        log.Printf("Error opening position: %v", err)
        return "", err
    }

    // Persist changes
    if err = h.Store.SaveForexRegistry(h.Registry); err != nil {
        log.Printf("Failed to save forex registry after opening position: %v", err)
        return "", err
    }
    log.Printf("Position opened successfully: Token ID %s", tokenID)
    return tokenID, nil
}

// ClosePosition closes an existing trading position and updates the registry.
func (h *ForexHandler) ClosePosition(tokenID string) error {
    if err := h.Registry.ClosePosition(tokenID); err != nil {
        log.Printf("Error closing position: %v", err)
        return err
    }

    // Persist changes
    if err := h.Store.SaveForexRegistry(h.Registry); err != nil {
        log.Printf("Failed to save forex registry after closing position: %v", err)
        return err
    }
    log.Printf("Position closed successfully: Token ID %s", tokenID)
    return nil
}

// UpdateForexPairRate updates the rate for a forex pair and persists the change.
func (h *ForexHandler) UpdateForexPairRate(pairId string, newRate float64) error {
    if err := h.Registry.UpdateForexPairRate(pairId, newRate); err != nil {
        log.Printf("Error updating forex pair rate: %v", err)
        return err
    }

    // Persist changes
    if err := h.Store.SaveForexRegistry(h.Registry); err != nil {
        log.Printf("Failed to save forex registry after rate update: %v", err)
        return err
    }
    log.Printf("Forex pair rate updated successfully: Pair ID %s, New Rate %f", pairId, newRate)
    return nil
}

// GetForexPairDetails retrieves and returns details of a specific forex pair.
func (h *ForexHandler) GetForexPairDetails(pairId string) (*ForexPair, error) {
    pair, exists := h.Registry.ForexPairs[pairId]
    if !exists {
        return nil, fmt.Errorf("forex pair not found: %s", pairId)
    }
    return pair, nil
}
