package syn3900

import (
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "log"
    "sync"
    "time"
)

// BenefitToken represents government benefits allocated to individuals.
type BenefitToken struct {
    TokenID         string    `json:"tokenId"`
    BenefitType     string    `json:"benefitType"`     // Type of benefit (e.g., healthcare, social security)
    Recipient       string    `json:"recipient"`       // Identity of the recipient
    Amount          float64   `json:"amount"`          // Amount or value of the benefit
    ValidFrom       time.Time `json:"validFrom"`       // Start date of benefit validity
    ValidUntil      time.Time `json:"validUntil"`      // Expiration date of the benefit
    IssuedDate      time.Time `json:"issuedDate"`
    Conditions      []string  `json:"conditions"`      // Conditions under which the benefits can be claimed
    Status          string    `json:"status"`          // Current status of the benefit (active, expired, suspended)
}

// BenefitRegistry manages all benefit tokens.
type BenefitRegistry struct {
    Benefits map[string]*BenefitToken
    mutex    sync.Mutex
}

// NewBenefitRegistry initializes a new registry for managing benefit tokens.
func NewBenefitRegistry() *BenefitRegistry {
    return &BenefitRegistry{
        Benefits: make(map[string]*BenefitToken),
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

// CreateBenefitToken issues a new benefit token to an individual.
func (r *BenefitRegistry) CreateBenefitToken(benefitType, recipient string, amount float64, validFrom, validUntil time.Time, conditions []string) (string, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    tokenID, err := GenerateTokenID()
    if err != nil {
        return "", err
    }

    now := time.Now()
    benefitToken := &BenefitToken{
        TokenID:     tokenID,
        BenefitType: benefitType,
        Recipient:   recipient,
        Amount:      amount,
        ValidFrom:   validFrom,
        ValidUntil:  validUntil,
        IssuedDate:  now,
        Conditions:  conditions,
        Status:      "active",
    }

    r.Benefits[tokenID] = benefitToken
    log.Printf("Benefit Token Created: %s at %s", tokenID, now)
    return tokenID, nil
}

// ChangeBenefitStatus changes the status of a benefit token (active, suspended).
func (r *BenefitRegistry) ChangeBenefitStatus(tokenID, status string) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    benefit, exists := r.Benefits[tokenID]
    if !exists {
        return fmt.Errorf("benefit token not found: %s", tokenID)
    }

    if status != "active" && status != "suspended" && status != "expired" {
        return fmt.Errorf("invalid status: %s", status)
    }

    benefit.Status = status
    log.Printf("Status of Benefit Token %s changed to %s", tokenID, status)
    return nil
}

// GetBenefitDetails retrieves the details of a specific benefit token.
func (r *BenefitRegistry) GetBenefitDetails(tokenID string) (*BenefitToken, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    benefit, exists := r.Benefits[tokenID]
    if !exists {
        return nil, fmt.Errorf("benefit token not found: %s", tokenID)
    }

    return benefit, nil
}
