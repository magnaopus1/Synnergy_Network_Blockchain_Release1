package syn2800

import (
    "errors"
    "fmt"
    "time"
)

// InsurancePolicy details the specifics of a life insurance policy.
type InsurancePolicy struct {
    PolicyID       string    `json:"policyId"`       // Unique identifier for the insurance policy
    Insured        string    `json:"insured"`        // Identifier for the person insured by the policy
    Beneficiary    string    `json:"beneficiary"`    // Identifier for the beneficiary of the policy
    Premium        float64   `json:"premium"`        // Monthly premium for the policy
    CoverageAmount float64   `json:"coverageAmount"` // Total amount of coverage provided by the policy
    StartDate      time.Time `json:"startDate"`      // Start date of the insurance coverage
    EndDate        time.Time `json:"endDate"`        // End date of the insurance coverage
    IsActive       bool      `json:"isActive"`       // Status of the policy (active or inactive)
}

// LifeInsuranceToken represents a tokenized version of a life insurance policy.
type LifeInsuranceToken struct {
    TokenID     string          `json:"tokenId"`     // Unique identifier for the token
    Policy      InsurancePolicy `json:"policy"`      // Detailed insurance policy
    Issuer      string          `json:"issuer"`      // Issuer of the token (insurance company)
    IssueDate   time.Time       `json:"issueDate"`   // Date when the token was issued
    Active      bool            `json:"active"`      // Is the token currently active?
}

// InsuranceLedger is the ledger managing all issued life insurance tokens.
type InsuranceLedger struct {
    Tokens map[string]LifeInsuranceToken // Maps Token IDs to LifeInsuranceTokens
}

// NewInsuranceLedger initializes a ledger for managing life insurance tokens.
func NewInsuranceLedger() *InsuranceLedger {
    return &InsuranceLedger{
        Tokens: make(map[string]LifeInsuranceToken),
    }
}

// IssueToken creates a new life insurance token.
func (il *InsuranceLedger) IssueToken(policy InsurancePolicy, issuer string) (*LifeInsuranceToken, error) {
    tokenID := fmt.Sprintf("LIT-%s", policy.PolicyID)
    if _, exists := il.Tokens[tokenID]; exists {
        return nil, fmt.Errorf("a token with ID %s already exists", tokenID)
    }

    newToken := LifeInsuranceToken{
        TokenID:   tokenID,
        Policy:    policy,
        Issuer:    issuer,
        IssueDate: time.Now(),
        Active:    true,
    }
    il.Tokens[tokenID] = newToken
    return &newToken, nil
}

// ActivateToken sets a life insurance token's status to active.
func (il *InsuranceLedger) ActivateToken(tokenID string) error {
    token, exists := il.Tokens[tokenID]
    if !exists {
        return errors.New("token does not exist")
    }

    token.Active = true
    il.Tokens[tokenID] = token
    return nil
}

// DeactivateToken sets a life insurance token's status to inactive.
func (il *InsuranceLedger) DeactivateToken(tokenID string) error {
    token, exists := il.Tokens[tokenID]
    if !exists {
        return errors.New("token does not exist")
    }

    token.Active = false
    il.Tokens[tokenID] = token
    return nil
}

// GetToken retrieves a specific life insurance token.
func (il *InsuranceLedger) GetToken(tokenID string) (LifeInsuranceToken, error) {
    token, exists := il.Tokens[tokenID]
    if !exists {
        return LifeInsuranceToken{}, fmt.Errorf("token with ID %s not found", tokenID)
    }
    return token, nil
}

// ListActiveTokens provides a list of all active life insurance tokens.
func (il *InsuranceLedger) ListActiveTokens() ([]LifeInsuranceToken, error) {
    var activeTokens []LifeInsuranceToken
    for _, token := range il.Tokens {
        if token.Active {
            activeTokens = append(activeTokens, token)
        }
    }
    if len(activeTokens) == 0 {
        return nil, fmt.Errorf("no active tokens found")
    }
    return activeTokens, nil
}

// ListTokensByOwner provides a list of all life insurance tokens for a specific owner.
func (il *InsuranceLedger) ListTokensByOwner(ownerID string) ([]LifeInsuranceToken, error) {
    var tokensByOwner []LifeInsuranceToken
    for _, token := range il.Tokens {
        if token.Policy.Beneficiary == ownerID || token.Policy.Insured == ownerID {
            tokensByOwner = append(tokensByOwner, token)
        }
    }
    if len(tokensByOwner) == 0 {
        return nil, fmt.Errorf("no tokens found for owner %s", ownerID)
    }
    return tokensByOwner, nil
}
