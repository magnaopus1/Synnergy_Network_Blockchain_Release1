package syn3300

import (
    "fmt"
    "log"
    "time"
)

// ETFHandler provides high-level operations on ETFs and their associated share tokens.
type ETFHandler struct {
    Registry *ETFRegistry
    Store    DataStore
}

// NewETFHandler initializes a new ETFHandler with a given registry and storage backend.
func NewETFHandler(registry *ETFRegistry, store DataStore) *ETFHandler {
    return &ETFHandler{
        Registry: registry,
        Store:    store,
    }
}

// CreateETF initializes and persists a new ETF in the registry.
func (h *ETFHandler) CreateETF(etfId, name string, totalShares float64) error {
    err := h.Registry.CreateETF(etfId, name, totalShares)
    if err != nil {
        log.Printf("Error creating ETF: %v", err)
        return err
    }
    // Persist changes
    err = h.Store.SaveETFRegistry(h.Registry)
    if err != nil {
        log.Printf("Failed to save ETF registry after creating ETF: %v", err)
        return err
    }
    log.Printf("ETF created successfully: %s", etfId)
    return nil
}

// IssueToken issues shares of an ETF to a holder and persists the changes.
func (h *ETFHandler) IssueToken(etfId, holder string, shares float64) (string, error) {
    tokenID, err := h.Registry.IssueShareToken(etfId, holder, shares)
    if err != nil {
        log.Printf("Error issuing token: %v", err)
        return "", err
    }
    // Persist changes
    err = h.Store.SaveETFRegistry(h.Registry)
    if err != nil {
        log.Printf("Failed to save ETF registry after issuing token: %v", err)
        return "", err
    }
    log.Printf("Token issued successfully: Token ID %s", tokenID)
    return tokenID, nil
}

// TransferShares transfers shares between holders and persists the changes.
func (h *ETFHandler) TransferShares(tokenID, newHolder string, shares float64) error {
    err := h.Registry.TransferShares(tokenID, newHolder, shares)
    if err != nil {
        log.Printf("Error transferring shares: %v", err)
        return err
    }
    // Persist changes
    err = h.Store.SaveETFRegistry(h.Registry)
    if err != nil {
        log.Printf("Failed to save ETF registry after transferring shares: %v", err)
        return err
    }
    log.Printf("Shares transferred successfully: Token ID %s", tokenID)
    return nil
}

// ListTokensByHolder lists all tokens for a specific holder.
func (h *ETFHandler) ListTokensByHolder(holder string) ([]ETFShareToken, error) {
    tokens := h.Registry.ListTokensByHolder(holder)
    if len(tokens) == 0 {
        return nil, fmt.Errorf("no tokens found for holder %s", holder)
    }
    return tokens, nil
}

// UpdateMarketPrices updates the price of all ETFs and persists the changes.
func (h *ETFHandler) UpdateMarketPrices() error {
    for _, etf := range h.Registry.ETFs {
        _, err := h.Registry.UpdateTokenPrice(etf.ETFID)
        if err != nil {
            log.Printf("Failed to update market price for ETF %s: %v", etf.ETFID, err)
            continue // Continue updating other ETFs even if one fails
        }
    }
    // Persist changes
    err := h.Store.SaveETFRegistry(h.Registry)
    if err != nil {
        log.Printf("Failed to save ETF registry after updating market prices: %v", err)
        return err
    }
    log.Println("Market prices updated successfully")
    return nil
}
