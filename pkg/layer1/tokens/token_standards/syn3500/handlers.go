package syn3500

import (
    "log"
)

// CurrencyTokenHandler provides high-level operations for managing currency tokens.
type CurrencyTokenHandler struct {
    Registry *CurrencyRegistry
    Store    DataStore
}

// NewCurrencyTokenHandler creates a new handler with a specified registry and storage system.
func NewCurrencyTokenHandler(registry *CurrencyRegistry, store DataStore) *CurrencyTokenHandler {
    return &CurrencyTokenHandler{
        Registry: registry,
        Store:    store,
    }
}

// CreateToken initializes a new currency token and saves it to the registry.
func (h *CurrencyTokenHandler) CreateToken(currencyCode, holder string, initialBalance float64) (string, error) {
    tokenID, err := h.Registry.CreateToken(currencyCode, holder, initialBalance)
    if err != nil {
        log.Printf("Error creating token: %v", err)
        return "", err
    }

    // Persist changes to the storage
    if err := h.Store.SaveCurrencyRegistry(h.Registry); err != nil {
        log.Printf("Failed to save currency registry after token creation: %v", err)
        return "", err
    }

    log.Printf("Token successfully created: %s", tokenID)
    return tokenID, nil
}

// TransferAmount facilitates transferring amounts between two tokens.
func (h *CurrencyTokenHandler) TransferAmount(fromTokenID, toTokenID string, amount float64) error {
    if err := h.Registry.Transfer(fromTokenID, toTokenID, amount); err != nil {
        log.Printf("Error transferring amount: %v", err)
        return err
    }

    // Persist changes to the storage
    if err := h.Store.SaveCurrencyRegistry(h.Registry); err != nil {
        log.Printf("Failed to save currency registry after transferring amount: %v", err)
        return err
    }

    log.Println("Transfer completed successfully")
    return nil
}

// UpdateTokenBalance updates the balance of a specific token.
func (h *CurrencyTokenHandler) UpdateTokenBalance(tokenID string, newBalance float64) error {
    if err := h.Registry.UpdateBalance(tokenID, newBalance); err != nil {
        log.Printf("Error updating token balance: %v", err)
        return err
    }

    // Persist changes
    if err := h.Store.SaveCurrencyRegistry(h.Registry); err != nil {
        log.Printf("Failed to save currency registry after updating balance: %v", err)
        return err
    }

    log.Printf("Balance updated successfully for token %s", tokenID)
    return nil
}

// GetTokenDetails retrieves the details for a specified token.
func (h *CurrencyTokenHandler) GetTokenDetails(tokenID string) (*CurrencyToken, error) {
    token, err := h.Registry.GetTokenDetails(tokenID)
    if err != nil {
        log.Printf("Error retrieving token details: %v", err)
        return nil, err
    }

    return token, nil
}
