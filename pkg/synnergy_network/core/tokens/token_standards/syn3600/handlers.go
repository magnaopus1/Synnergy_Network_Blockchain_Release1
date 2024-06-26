package syn3600

import (
    "log"
    "time"
)

// FuturesHandler manages operations related to futures tokens.
type FuturesHandler struct {
    Registry *FuturesRegistry
    Store    DataStore
}

// NewFuturesHandler initializes a new FuturesHandler with a given registry and storage.
func NewFuturesHandler(registry *FuturesRegistry, store DataStore) *FuturesHandler {
    return &FuturesHandler{
        Registry: registry,
        Store:    store,
    }
}

// CreateFutureToken creates and stores a new futures token.
func (h *FuturesHandler) CreateFutureToken(asset string, quantity, strikePrice float64, expiryDate string, holder string) (string, error) {
    expiry, err := time.Parse(time.RFC3339, expiryDate)
    if err != nil {
        log.Printf("Invalid expiry date format: %v", err)
        return "", err
    }

    tokenID, err := h.Registry.CreateFutureToken(asset, quantity, strikePrice, expiry, holder)
    if err != nil {
        log.Printf("Error creating future token: %v", err)
        return "", err
    }

    // Save changes to storage
    if err := h.Store.SaveFuturesRegistry(h.Registry); err != nil {
        log.Printf("Failed to save futures registry after creating token: %v", err)
        return "", err
    }

    log.Printf("Future token successfully created: %s", tokenID)
    return tokenID, nil
}

// SettleFuture marks a futures contract as settled and updates the registry.
func (h *FuturesHandler) SettleFuture(tokenID string, settlementPrice float64) error {
    if err := h.Registry.SettleFuture(tokenID, settlementPrice); err != nil {
        log.Printf("Error settling future token: %v", err)
        return err
    }

    // Save changes to storage
    if err := h.Store.SaveFuturesRegistry(h.Registry); err != nil {
        log.Printf("Failed to save futures registry after settling future: %v", err)
        return err
    }

    log.Printf("Future token successfully settled: %s", tokenID)
    return nil
}

// GetFutureDetails retrieves details of a specific futures token.
func (h *FuturesHandler) GetFutureDetails(tokenID string) (*FutureToken, error) {
    future, err := h.Registry.GetFutureDetails(tokenID)
    if err != nil {
        log.Printf("Error retrieving future token details: %v", err)
        return nil, err
    }

    return future, nil
}
