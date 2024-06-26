package syn4900

import (
    "fmt"
    "log"
    "time"
)

// AgriculturalTokenHandler handles interactions with agricultural tokens.
type AgriculturalTokenHandler struct {
    Registry *AgriculturalRegistry
    Store    DataStore
}

// NewAgriculturalTokenHandler initializes a handler with dependencies.
func NewAgriculturalTokenHandler(registry *AgriculturalRegistry, store DataStore) *AgriculturalTokenHandler {
    return &AgriculturalTokenHandler{
        Registry: registry,
        Store:    store,
    }
}

// CreateToken creates a new agricultural token and saves the updated registry.
func (h *AgriculturalTokenHandler) CreateToken(assetType string, quantity float64, owner, origin, certification string, harvestDate, expiryDate time.Time) (string, error) {
    tokenID, err := h.Registry.CreateAgriculturalToken(assetType, quantity, owner, origin, certification, harvestDate, expiryDate)
    if err != nil {
        log.Printf("Failed to create token: %v", err)
        return "", err
    }

    if err := h.Store.SaveRegistry(h.Registry); err != nil {
        log.Printf("Failed to save registry after creating token: %v", err)
        return "", err
    }

    log.Printf("Token created successfully: %s", tokenID)
    return tokenID, nil
}

// UpdateTokenStatus changes the status of a token and saves the updated registry.
func (h *AgriculturalTokenHandler) UpdateTokenStatus(tokenID, status string) error {
    if err := h.Registry.UpdateTokenStatus(tokenID, status); err != nil {
        log.Printf("Failed to update token status: %v", err)
        return err
    }

    if err := h.Store.SaveRegistry(h.Registry); err != nil {
        log.Printf("Failed to save registry after updating token status: %v", err)
        return err
    }

    log.Printf("Token status updated successfully: %s", tokenID)
    return nil
}

// GetTokenDetails retrieves details for a specific token.
func (h *AgriculturalTokenHandler) GetTokenDetails(tokenID string) (*AgriculturalToken, error) {
    token, err := h.Registry.GetTokenDetails(tokenID)
    if err != nil {
        log.Printf("Failed to retrieve token details: %v", err)
        return nil, err
    }

    return token, nil
}

// TransferToken handles the transfer of ownership of a token.
func (h *AgriculturalTokenHandler) TransferToken(tokenID, newOwner string) error {
    token, err := h.GetTokenDetails(tokenID)
    if err != nil {
        return err
    }

    // Record the transfer as a transaction
    transaction := Transaction{
        TransactionID: fmt.Sprintf("%s-to-%s-%d", token.Owner, newOwner, time.Now().Unix()),
        Timestamp:     time.Now(),
        From:          token.Owner,
        To:            newOwner,
        Quantity:      token.Quantity,
        Description:   fmt.Sprintf("Transfer of %s from %s to %s", token.AssetType, token.Owner, newOwner),
    }
    token.Owner = newOwner
    token.TransactionHistory = append(token.TransactionHistory, transaction)

    if err := h.Store.SaveRegistry(h.Registry); err != nil {
        log.Printf("Failed to save registry after transferring token: %v", err)
        return err
    }

    log.Printf("Token transferred successfully from %s to %s", transaction.From, transaction.To)
    return nil
}
