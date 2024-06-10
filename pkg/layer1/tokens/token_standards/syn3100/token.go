package syn3100

import (
    "errors"
    "fmt"
    "time"
)

// EmploymentContract represents the details of an employment agreement, including contract types.
type EmploymentContract struct {
    ContractID       string    `json:"contractId"`       // Unique identifier for the employment contract
    EmployeeID       string    `json:"employeeId"`       // Identifier for the employee
    EmployerID       string    `json:"employerId"`       // Identifier for the employer
    Position         string    `json:"position"`         // Job position or title
    Salary           float64   `json:"salary"`           // Monthly salary
    ContractType     string    `json:"contractType"`     // Type of contract: full-time, part-time, contractor
    StartDate        time.Time `json:"startDate"`        // Effective start date of employment
    EndDate          time.Time `json:"endDate"`          // Effective end date of employment, if applicable
    Benefits         []string  `json:"benefits"`         // List of benefits included in the employment
    ContractTerms    string    `json:"contractTerms"`    // Additional terms and conditions
    IsActive         bool      `json:"isActive"`         // Status of the employment contract
}

// EmploymentToken encapsulates an employment contract into a tokenized form.
type EmploymentToken struct {
    TokenID     string             `json:"tokenId"`     // Unique identifier for the token
    Contract    EmploymentContract `json:"contract"`    // Detailed employment contract
    IssuedDate  time.Time          `json:"issuedDate"`  // Date when the token was issued
}

// EmploymentLedger manages the tokens associated with employment contracts.
type EmploymentLedger struct {
    Tokens map[string]EmploymentToken // Maps Token IDs to EmploymentTokens
}

// NewEmploymentLedger initializes a new ledger for managing employment tokens.
func NewEmploymentLedger() *EmploymentLedger {
    return &EmploymentLedger{
        Tokens: make(map[string]EmploymentToken),
    }
}

// IssueToken creates a new employment token based on the provided contract details.
func (el *EmploymentLedger) IssueToken(contract EmploymentContract) (*EmploymentToken, error) {
    tokenID := fmt.Sprintf("EMP-%s-%s", contract.EmployerID, contract.EmployeeID)
    if _, exists := el.Tokens[tokenID]; exists {
        return nil, fmt.Errorf("an employment token with ID %s already exists", tokenID)
    }

    newToken := EmploymentToken{
        TokenID:    tokenID,
        Contract:   contract,
        IssuedDate: time.Now(),
    }

    el.Tokens[tokenID] = newToken
    return &newToken, nil
}

// UpdateContract modifies the terms of an existing employment contract.
func (el *EmploymentLedger) UpdateContract(tokenID string, newTerms string) error {
    token, exists := el.Tokens[tokenID]
    if !exists {
        return errors.New("employment token not found")
    }

    if !token.Contract.IsActive {
        return fmt.Errorf("employment contract %s is not active", tokenID)
    }

    token.Contract.ContractTerms = newTerms
    el.Tokens[tokenID] = token
    return nil
}

// DeactivateContract marks an employment contract as terminated.
func (el *EmploymentLedger) DeactivateContract(tokenID string) error {
    token, exists := el.Tokens[tokenID]
    if !exists {
        return errors.New("employment token not found")
    }

    token.Contract.IsActive = false
    el.Tokens[tokenID] = token
    return nil
}

// GetToken retrieves an employment token by its ID.
func (el *EmploymentLedger) GetToken(tokenID string) (EmploymentToken, error) {
    token, exists := el.Tokens[tokenID]
    if !exists {
        return EmploymentToken{}, fmt.Errorf("employment token with ID %s not found", tokenID)
    }
    return token, nil
}
