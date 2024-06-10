package syn4200

import (
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"
    "time"
)

// CharityToken represents donations or contributions for specific charitable causes.
type CharityToken struct {
    TokenID      string    `json:"tokenId"`
    CampaignName string    `json:"campaignName"` // Name of the fundraising or charity campaign
    Donor        string    `json:"donor"`        // Identity of the donor
    Amount       float64   `json:"amount"`       // Amount donated
    DonationDate time.Time `json:"donationDate"`
    Purpose      string    `json:"purpose"`      // Specific purpose or project the donation supports
    ExpiryDate   time.Time `json:"expiryDate"`   // When the token or campaign expires
    Status       string    `json:"status"`       // Current status (active, completed, expired)
    Traceable    bool      `json:"traceable"`    // If true, donations can be traced to specific uses
}

// CharityRegistry manages all charity tokens.
type CharityRegistry struct {
    Tokens map[string]*CharityToken
    mutex  sync.Mutex
}

// NewCharityRegistry initializes a new registry for managing charity tokens.
func NewCharityRegistry() *CharityRegistry {
    return &CharityRegistry{
        Tokens: make(map[string]*CharityToken),
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

// CreateCharityToken issues a new charity token for a donation.
func (r *CharityRegistry) CreateCharityToken(campaignName, donor string, amount float64, purpose string, expiryDate time.Time, traceable bool) (string, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    tokenID, err := GenerateTokenID()
    if err != nil {
        return "", err
    }

    now := time.Now()
    charityToken := &CharityToken{
        TokenID:      tokenID,
        CampaignName: campaignName,
        Donor:        donor,
        Amount:       amount,
        DonationDate: now,
        Purpose:      purpose,
        ExpiryDate:   expiryDate,
        Status:       "active",
        Traceable:    traceable,
    }

    r.Tokens[tokenID] = charityToken
    fmt.Printf("New charity token created on %v: %+v\n", now, charityToken)
    return tokenID, nil
}

// UpdateCharityTokenStatus updates the status of a charity token.
func (r *CharityRegistry) UpdateCharityTokenStatus(tokenID, status string) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    token, exists := r.Tokens[tokenID]
    if !exists {
        return errors.New("charity token not found")
    }

    token.Status = status
    fmt.Printf("Updated charity token status for %s to %s\n", tokenID, status)
    return nil
}

// GetCharityTokenDetails retrieves details for a specific charity token.
func (r *CharityRegistry) GetCharityTokenDetails(tokenID string) (*CharityToken, error) {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    token, exists := r.Tokens[tokenID]
    if !exists {
        return nil, fmt.Errorf("charity token not found: %s", tokenID)
    }

    return token, nil
}
