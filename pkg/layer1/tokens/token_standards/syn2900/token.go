package syn2900

import (
    "errors"
    "fmt"
    "time"
)

// InsuranceCoverage defines the specific coverage details of an insurance policy.
type InsuranceCoverage struct {
    Type          string  `json:"type"`           // Type of coverage (e.g., property, liability, health, cybersecurity)
    CoverageLimit float64 `json:"coverageLimit"`  // Maximum amount covered
    Deductible    float64 `json:"deductible"`     // Deductible amount before payouts begin
}

// InsurancePolicy represents the details of an insurance policy tokenized on the blockchain.
type InsurancePolicy struct {
    PolicyID        string             `json:"policyId"`        // Unique identifier for the policy
    Issuer          string             `json:"issuer"`          // Issuer of the policy, typically an insurance company
    Owner           string             `json:"owner"`           // Owner of the policy, typically the insured party
    Coverages       []InsuranceCoverage `json:"coverages"`      // List of coverages included in the policy
    Premium         float64            `json:"premium"`         // Premium amount to be paid periodically
    PolicyStartDate time.Time          `json:"policyStartDate"` // Start date of the policy
    PolicyEndDate   time.Time          `json:"policyEndDate"`   // End date of the policy
    IsActive        bool               `json:"isActive"`        // Status of the policy (active or inactive)
}

// InsuranceToken ties an insurance policy with blockchain-specific properties.
type InsuranceToken struct {
    TokenID    string          `json:"tokenId"`    // Unique identifier for the token
    Policy     InsurancePolicy `json:"policy"`     // Detailed insurance policy
    IssueDate  time.Time       `json:"issueDate"`  // Date when the token was issued
}

// InsuranceLedger manages the issuance, storage, and lifecycle of insurance tokens.
type InsuranceLedger struct {
    Tokens map[string]InsuranceToken // Maps Token IDs to InsuranceTokens
}

// NewInsuranceLedger creates a new ledger for managing insurance tokens.
func NewInsuranceLedger() *InsuranceLedger {
    return &InsuranceLedger{
        Tokens: make(map[string]InsuranceToken),
    }
}

// IssueToken issues a new insurance token with a comprehensive policy attached.
func (il *InsuranceLedger) IssueToken(policy InsurancePolicy) (*InsuranceToken, error) {
    tokenID := fmt.Sprintf("INS-%s", policy.PolicyID)
    if _, exists := il.Tokens[tokenID]; exists {
        return nil, fmt.Errorf("an insurance token with ID %s already exists", tokenID)
    }

    newToken := InsuranceToken{
        TokenID:   tokenID,
        Policy:    policy,
        IssueDate: time.Now(),
    }

    il.Tokens[tokenID] = newToken
    return &newToken, nil
}

// ActivatePolicy activates an insurance policy associated with a given token.
func (il *InsuranceLedger) ActivatePolicy(tokenID string) error {
    token, exists := il.Tokens[tokenID]
    if !exists {
        return errors.New("insurance token not found")
    }

    if token.Policy.IsActive {
        return fmt.Errorf("insurance policy %s is already active", tokenID)
    }

    token.Policy.IsActive = true
    il.Tokens[tokenID] = token
    return nil
}

// DeactivatePolicy deactivates an insurance policy, typically when it expires or is terminated.
func (il *InsuranceLedger) DeactivatePolicy(tokenID string) error {
    token, exists := il.Tokens[tokenID]
    if !exists {
        return errors.New("insurance token not found")
    }

    if !token.Policy.IsActive {
        return fmt.Errorf("insurance policy %s is already inactive", tokenID)
    }

    token.Policy.IsActive = false
    il.Tokens[tokenID] = token
    return nil
}

// GetToken retrieves an insurance token by its ID.
func (il *InsuranceLedger) GetToken(tokenID string) (InsuranceToken, error) {
    token, exists := il.Tokens[tokenID]
    if !exists {
        return InsuranceToken{}, fmt.Errorf("insurance token with ID %s not found", tokenID)
    }
    return token, nil
}

// ListActivePolicies lists all active insurance policies.
func (il *InsuranceLedger) ListActivePolicies() ([]InsuranceToken, error) {
    var activeTokens []InsuranceToken
    for _, token := range il.Tokens {
        if token.Policy.IsActive {
            activeTokens = append(activeTokens, token)
        }
    }
    if len(activeTokens) == 0 {
        return nil, fmt.Errorf("no active insurance policies found")
    }
    return activeTokens, nil
}
