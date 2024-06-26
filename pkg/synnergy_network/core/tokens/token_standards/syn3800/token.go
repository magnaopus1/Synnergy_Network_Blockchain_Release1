package syn3800

import (
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"
)

// GrantToken represents a government grant allocated for specific purposes.
type GrantToken struct {
    TokenID         string    `json:"tokenId"`
    GrantName       string    `json:"grantName"`       // Name of the grant or subsidy
    Beneficiary     string    `json:"beneficiary"`     // Entity that receives the grant
    Amount          float64   `json:"amount"`          // Total amount of the grant
    DisbursedAmount float64   `json:"disbursedAmount"` // Amount that has been disbursed
    Purpose         string    `json:"purpose"`         // Specific purpose of the grant
    ExpiryDate      time.Time `json:"expiryDate"`      // Expiration date of the grant
    CreationDate    time.Time `json:"creationDate"`
    Status          string    `json:"status"`          // Status of the grant (active, completed, expired)
    Conditions      []string  `json:"conditions"`      // Conditions that must be met to disburse funds
}

// GrantRegistry manages all grant tokens.
type GrantRegistry struct {
    Grants map[string]*GrantToken
    mutex  sync.Mutex
}

// NewGrantRegistry creates a new registry for managing grant tokens.
func NewGrantRegistry() *GrantRegistry {
    return &GrantRegistry{
        Grants: make(map[string]*GrantToken),
    }
}

// GenerateTokenID creates a secure, unique token ID.
func GenerateTokenID() (string, error) {
    b := make([]byte, 16) // 128-bit
    _, err := rand.Read(b)
    if err != nil {
        return "", fmt.Errorf("error generating token ID: %v", err)
    }
    return hex.EncodeToString(b), nil
}

// CreateGrantToken issues a new grant token.
func (r *GrantRegistry) CreateGrantToken(grantName, beneficiary, purpose string, amount float64, expiryDate time.Time, conditions []string) (string, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    tokenID, err := GenerateTokenID()
    if err != nil {
        return "", err
    }

    grantToken := &GrantToken{
        TokenID:         tokenID,
        GrantName:       grantName,
        Beneficiary:     beneficiary,
        Amount:          amount,
        DisbursedAmount: 0,
        Purpose:         purpose,
        ExpiryDate:      expiryDate,
        CreationDate:    time.Now(),
        Status:          "active",
        Conditions:      conditions,
    }

    r.Grants[tokenID] = grantToken
    return tokenID, nil
}

// DisburseFunds checks conditions and disburses funds to the grant token.
func (r *GrantRegistry) DisburseFunds(tokenID string, amount float64, metConditions []string) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    grant, exists := r.Grants[tokenID]
    if !exists {
        return errors.New("grant token not found")
    }

    if grant.Status != "active" {
        return errors.New("grant is not active")
    }

    // Check if all required conditions have been met
    if !areConditionsMet(grant.Conditions, metConditions) {
        return errors.New("all conditions for disbursement are not met")
    }

    if amount > grant.Amount-grant.DisbursedAmount {
        return errors.New("disbursement amount exceeds available grant funds")
    }

    grant.DisbursedAmount += amount
    if grant.DisbursedAmount == grant.Amount {
        grant.Status = "completed"
    }
    return nil
}

// areConditionsMet checks if all required conditions are met
func areConditionsMet(required, provided []string) bool {
    requiredSet := make(map[string]bool)
    for _, condition := range required {
        requiredSet[condition] = true
    }
    for _, condition := range provided {
        if _, found := requiredSet[condition]; found {
            delete(requiredSet, condition)
        }
    }
    return len(requiredSet) == 0
}

// GetGrantDetails retrieves the details of a specific grant token.
func (r *GrantRegistry) GetGrantDetails(tokenID string) (*GrantToken, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    grant, exists := r.Grants[tokenID]
    if !exists {
        return nil, fmt.Errorf("grant token not found: %s", tokenID)
    }

    return grant, nil
}
