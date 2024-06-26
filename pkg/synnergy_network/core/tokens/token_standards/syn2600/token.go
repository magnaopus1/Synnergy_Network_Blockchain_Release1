package syn2600

import (
    "errors"
    "fmt"
    "time"
)

// FinancialAsset represents the type of asset an investor token is tied to.
type FinancialAsset struct {
    AssetID    string    `json:"assetId"`    // Unique identifier for the asset
    Type       string    `json:"type"`       // Type of asset (loan, bond, security)
    TotalValue float64   `json:"totalValue"` // Total value of the financial asset
}

// InvestorToken represents a token that provides ownership or investment rights.
type InvestorToken struct {
    TokenID      string          `json:"tokenId"`      // Unique identifier for the token
    Asset        FinancialAsset  `json:"asset"`        // Associated financial asset
    Owner        string          `json:"owner"`        // Owner's identifier
    Shares       float64         `json:"shares"`       // Number of shares the token represents
    IssuedDate   time.Time       `json:"issuedDate"`   // Date when the token was issued
    ExpiryDate   time.Time       `json:"expiryDate"`   // Expiry date of the token, if applicable
    Active       bool            `json:"active"`       // Status to indicate if the token is active
    TotalSupply  float64         `json:"totalSupply"`  // Total supply of tokens for the asset
}

// InvestmentLedger manages the lifecycle and ownership of investor tokens.
type InvestmentLedger struct {
    Tokens map[string]InvestorToken  // Maps Token IDs to InvestorTokens
    TotalSupplyByAsset map[string]float64 // Maps asset IDs to their total token supply
}

// NewInvestmentLedger initializes a new ledger for managing investor tokens.
func NewInvestmentLedger() *InvestmentLedger {
    return &InvestmentLedger{
        Tokens: make(map[string]InvestorToken),
        TotalSupplyByAsset: make(map[string]float64),
    }
}

// IssueToken creates and registers a new investor token.
func (il *InvestmentLedger) IssueToken(token InvestorToken) error {
    if _, exists := il.Tokens[token.TokenID]; exists {
        return fmt.Errorf("token with ID %s already exists", token.TokenID)
    }

    // Ensuring that the total issued shares do not exceed the declared total supply for the asset
    if currentSupply, ok := il.TotalSupplyByAsset[token.Asset.AssetID]; ok {
        if currentSupply + token.Shares > token.TotalSupply {
            return fmt.Errorf("issuing this token exceeds the total supply limit for asset %s", token.Asset.AssetID)
        }
    }

    token.IssuedDate = time.Now()
    token.Active = true
    il.Tokens[token.TokenID] = token
    il.TotalSupplyByAsset[token.Asset.AssetID] += token.Shares
    return nil
}

// RedeemToken handles the redemption process of a token, typically at maturity or expiry.
func (il *InvestmentLedger) RedeemToken(tokenID string) error {
    token, exists := il.Tokens[tokenID]
    if !exists {
        return errors.New("token not found")
    }

    if token.ExpiryDate.After(time.Now()) {
        return fmt.Errorf("token %s not yet matured", tokenID)
    }

    token.Active = false
    il.Tokens[tokenID] = token
    il.TotalSupplyByAsset[token.Asset.AssetID] -= token.Shares
    return nil
}

// TransferToken changes the ownership of an investor token to a new owner.
func (il *InvestmentLedger) TransferToken(tokenID, newOwner string) error {
    token, exists := il.Tokens[tokenID]
    if !exists {
        return errors.New("token does not exist")
    }

    token.Owner = newOwner
    il.Tokens[tokenID] = token
    return nil
}

// GetToken retrieves an investor token by its ID.
func (il *InvestmentLedger) GetToken(tokenID string) (InvestorToken, error) {
    token, exists := il.Tokens[tokenID]
    if !exists {
        return InvestorToken{}, fmt.Errorf("token with ID %s not found", tokenID)
    }
    return token, nil
}

// ListTokensByOwner returns all tokens currently owned by a specific entity.
func (il *InvestmentLedger) ListTokensByOwner(owner string) ([]InvestorToken, error) {
    var ownedTokens []InvestorToken
    for _, token := range il.Tokens {
        if token.Owner == owner && token.Active {
            ownedTokens = append(ownedTokens, token)
        }
    }
    if len(ownedTokens) == 0 {
        return nil, fmt.Errorf("no active tokens found for owner %s", owner)
    }
    return ownedTokens, nil
}
