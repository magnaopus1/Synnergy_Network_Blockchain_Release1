package factory

import (
    "errors"
    "sync"
    "time"

    "github.com/google/uuid"
    "github.com/synnergy_network/core/tokens/token_standards/syn223/assets"
    "github.com/synnergy_network/core/tokens/token_standards/syn223/ledger"
    "github.com/synnergy_network/core/tokens/token_standards/syn223/transactions"
    "github.com/synnergy_network/core/tokens/token_standards/syn223/security"
    "github.com/synnergy_network/utils"
)

// TokenFactory is responsible for creating new tokens and managing their metadata.
type TokenFactory struct {
    mu                sync.Mutex
    metadataStore     *assets.MetadataStore
    ledger            *ledger.Ledger
    securityManager   *security.SecurityManager
}

// NewTokenFactory initializes a new TokenFactory instance.
func NewTokenFactory(metadataStore *assets.MetadataStore, ledger *ledger.Ledger, securityManager *security.SecurityManager) *TokenFactory {
    return &TokenFactory{
        metadataStore: metadataStore,
        ledger:        ledger,
        securityManager: securityManager,
    }
}

// TokenParams represents the parameters for creating a new token.
type TokenParams struct {
    Name        string
    Symbol      string
    TotalSupply uint64
    Decimals    uint8
    Owner       string
}

// CreateToken creates a new token with the specified parameters.
func (tf *TokenFactory) CreateToken(params TokenParams) (string, error) {
    tf.mu.Lock()
    defer tf.mu.Unlock()

    // Validate input parameters
    if params.Name == "" || params.Symbol == "" || params.TotalSupply == 0 || params.Owner == "" {
        return "", errors.New("invalid token parameters")
    }

    // Generate a unique ID for the token
    tokenID := uuid.New().String()

    // Create token metadata
    metadata := assets.TokenMetadata{
        ID:          tokenID,
        Name:        params.Name,
        Symbol:      params.Symbol,
        TotalSupply: params.TotalSupply,
        Decimals:    params.Decimals,
    }

    // Add metadata to the store
    if err := tf.metadataStore.AddMetadata(metadata); err != nil {
        return "", err
    }

    // Initialize the balance of the owner
    if err := tf.ledger.UpdateBalance(params.Owner, tokenID, params.TotalSupply); err != nil {
        return "", err
    }

    // Log the creation transaction
    creationTx := transactions.Transaction{
        ID:          uuid.New().String(),
        TokenID:     tokenID,
        From:        "0x0", // representing the creation event
        To:          params.Owner,
        Amount:      params.TotalSupply,
        Timestamp:   time.Now().Unix(),
        Metadata:    "Token creation",
        IsCreation:  true,
    }
    if err := tf.ledger.LogTransaction(creationTx); err != nil {
        return "", err
    }

    return tokenID, nil
}

// MintTokens mints additional tokens for an existing token.
func (tf *TokenFactory) MintTokens(tokenID, to string, amount uint64) error {
    tf.mu.Lock()
    defer tf.mu.Unlock()

    // Validate token existence
    if _, err := tf.metadataStore.GetMetadata(tokenID); err != nil {
        return err
    }

    // Update the total supply in the metadata
    metadata, _ := tf.metadataStore.GetMetadata(tokenID)
    metadata.TotalSupply += amount
    if err := tf.metadataStore.UpdateMetadata(metadata); err != nil {
        return err
    }

    // Update the balance of the recipient
    if err := tf.ledger.UpdateBalance(to, tokenID, amount); err != nil {
        return err
    }

    // Log the minting transaction
    mintTx := transactions.Transaction{
        ID:          uuid.New().String(),
        TokenID:     tokenID,
        From:        "0x0", // representing the minting event
        To:          to,
        Amount:      amount,
        Timestamp:   time.Now().Unix(),
        Metadata:    "Token minting",
        IsCreation:  false,
    }
    if err := tf.ledger.LogTransaction(mintTx); err != nil {
        return err
    }

    return nil
}

// BurnTokens burns existing tokens, reducing the total supply.
func (tf *TokenFactory) BurnTokens(tokenID, from string, amount uint64) error {
    tf.mu.Lock()
    defer tf.mu.Unlock()

    // Validate token existence
    if _, err := tf.metadataStore.GetMetadata(tokenID); err != nil {
        return err
    }

    // Check the balance of the sender
    if balance, err := tf.ledger.GetBalance(from, tokenID); err != nil || balance < amount {
        return errors.New("insufficient balance to burn tokens")
    }

    // Update the total supply in the metadata
    metadata, _ := tf.metadataStore.GetMetadata(tokenID)
    metadata.TotalSupply -= amount
    if err := tf.metadataStore.UpdateMetadata(metadata); err != nil {
        return err
    }

    // Update the balance of the sender
    if err := tf.ledger.UpdateBalance(from, tokenID, -amount); err != nil {
        return err
    }

    // Log the burning transaction
    burnTx := transactions.Transaction{
        ID:          uuid.New().String(),
        TokenID:     tokenID,
        From:        from,
        To:          "0x0", // representing the burning event
        Amount:      amount,
        Timestamp:   time.Now().Unix(),
        Metadata:    "Token burning",
        IsCreation:  false,
    }
    if err := tf.ledger.LogTransaction(burnTx); err != nil {
        return err
    }

    return nil
}
